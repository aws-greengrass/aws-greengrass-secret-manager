/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager;

import com.aws.greengrass.config.Topic;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import com.aws.greengrass.secretmanager.exception.FileSecretStoreException;
import com.aws.greengrass.secretmanager.exception.SecretCryptoException;
import com.aws.greengrass.secretmanager.exception.SecretManagerException;
import com.aws.greengrass.secretmanager.exception.v1.GetSecretException;
import com.aws.greengrass.secretmanager.kernel.KernelClient;
import com.aws.greengrass.secretmanager.model.AWSSecretResponse;
import com.aws.greengrass.secretmanager.model.SecretConfiguration;
import com.aws.greengrass.secretmanager.model.SecretDocument;
import com.aws.greengrass.secretmanager.store.FileSecretStore;
import com.aws.greengrass.secretmanager.store.SecretStore;
import com.aws.greengrass.util.Coerce;
import com.aws.greengrass.util.Utils;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.aws.greengrass.model.SecretValue;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;
import javax.inject.Inject;

import static com.aws.greengrass.componentmanager.KernelConfigResolver.CONFIGURATION_CONFIG_KEY;
import static com.aws.greengrass.secretmanager.SecretManagerService.SECRETS_TOPIC;

/**
 * Class which holds the business logic for secret management. This class always holds a copy of actual AWS secrets
 * response in memory to serve requests. Since v1 and v2 IPC models are different this class directly translates the AWS
 * responses in memory to v1/v2 models as part of IPC requests. Secrets are stored encrypted for availability across
 * restarts. In memory copy is always plain text.
 */
public class SecretManager {
    private static final String LATEST_LABEL = "AWSCURRENT";
    public static final String VALID_SECRET_ARN_PATTERN =
            "arn:([^:]+):secretsmanager:[a-z0-9\\-]+:[0-9]{12}:secret:([a-zA-Z0-9\\\\]+/)*"
                    + "[a-zA-Z0-9/_+=,.@\\-]+(-[a-zA-Z0-9]+)?";
    private static final String secretNotFoundErr = "Secret not found ";
    private static final String secretNotConfiguredErr = "Secret not configured ";
    private static final String IPC_REQUEST_REFRESH_FIELD = "refresh";
    private final Logger logger = LogManager.getLogger(SecretManager.class);
    // Cache which holds aws secrets result
    private final Map<String, GetSecretValueResponse> cache = new HashMap<>();
    private final Map<String, String> nameToArnMap = new HashMap<>();

    private final AWSSecretClient secretClient;
    private final SecretStore<SecretDocument, AWSSecretResponse> secretStore;
    private final LocalStoreMap localStoreMap;
    private final KernelClient kernelClient;
    private static final ObjectMapper OBJECT_MAPPER =
            new ObjectMapper().configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);

    private final Object syncFromCloudLockObject = new Object();
    private final Object cacheLockObject = new Object();

    /**
     * Constructor.
     *
     * @param secretClient client for aws secrets.
     * @param dao          dao for persistent store.
     */
    @Inject
    SecretManager(AWSSecretClient secretClient, FileSecretStore dao, KernelClient kernelClient, LocalStoreMap map) {
        this.secretStore = dao;
        this.secretClient = secretClient;
        this.localStoreMap = map;
        this.kernelClient = kernelClient;
    }

    private List<SecretConfiguration> getSecretConfiguration() {
        Topic secretParam =
                this.kernelClient.getConfig().lookupTopics("services", SecretManagerService.SECRET_MANAGER_SERVICE_NAME)
                        .lookup(CONFIGURATION_CONFIG_KEY, SECRETS_TOPIC);
        try {
            List<SecretConfiguration> configuredSecrets =
                    OBJECT_MAPPER.convertValue(secretParam.toPOJO(), new TypeReference<List<SecretConfiguration>>() {
                    });
            if (!Objects.isNull(configuredSecrets)) {
                configuredSecrets.forEach((secret) -> {
                    if (secret.getLabels() == null) {
                        secret.setLabels(Collections.singletonList(LATEST_LABEL));
                    }
                    if (!secret.getLabels().contains(LATEST_LABEL)) {
                        secret.getLabels().add(LATEST_LABEL);
                    }
                });
                return configuredSecrets;
            }
            logger.atError().kv("secrets", secretParam.toString()).log("Unable to parse secrets configured");
        } catch (IllegalArgumentException e) {
            logger.atError().kv("node", secretParam.getFullName()).kv("value", secretParam).setCause(e)
                    .log("Unable to parse secrets configured");
        }
        return new ArrayList<>();
    }

    /**
     * When the component is installed, it firsts cleans up/syncs the existing local secrets as per the component
     * configuration. It then tries to download latest secret from cloud for each configured secret-label. It then
     * updates the local store with that secret and refreshes the cache.
     * @throws RuntimeException secret manager exceptions
     */
    public void syncFromCloud() {
        synchronized (syncFromCloudLockObject) {
            List<SecretConfiguration> secretConfiguration = getSecretConfiguration();
            localStoreMap.syncWithConfig(secretConfiguration);
            try {
                reloadCache();
            } catch (SecretManagerException e) {
                if (e.getCause() instanceof FileSecretStoreException) {
                    // Happens when the local store is corrupted. Local secret cache is cleared by the time this
                    // exception is thrown as it is no longer valid. New secrets will be downloaded as needed. So, just
                    // log and proceed.
                    logger.atError().log("Exception occurred while updating the local secret cache.");
                } else {
                    // Should never happen. Throw any unexpected exceptions.
                    throw new RuntimeException(e);
                }
            }

            for (SecretConfiguration configuredSecret : secretConfiguration) {
                String arn = configuredSecret.getArn();
                if (!isSecretIdArn(arn)) {
                    logger.atWarn().kv("Secret ", arn).log("Skipping invalid secret arn configured");
                    continue;
                }
                configuredSecret.getLabels().forEach((label) -> {
                    // Download latest secret from cloud for each configured label
                    refreshSecretFromCloud(arn, label);
                });
            }
        }
    }

    /**
     * Load secrets into cache from the local store. This method can be called from several threads 1. Service thread
     * during start up 2. IPC thread when refresh is set to true. 3. Secret manager config subscription thread -
     * syncFromCloud 4. scheduler thread that periodically refreshes secrets - syncFromCloud
     *
     * @throws SecretManagerException when there are issues reading from disk
     */
    public void reloadCache() throws SecretManagerException {
        synchronized (cacheLockObject) {
            logger.atDebug("clear-local-secret-cache").log();
            nameToArnMap.clear();
            cache.clear();
            logger.atDebug("load-secret-local-store").log();
            // read the db
            List<AWSSecretResponse> secrets = secretStore.getAll().getSecrets();
            if (!Utils.isEmpty(secrets)) {
                for (AWSSecretResponse secretResult : secrets) {
                    nameToArnMap.put(secretResult.getName(), secretResult.getArn());
                    loadCache(secretResult);
                }
            }
        }
    }

    /*
    * Cache holds multiple references of the secret with different keys for fast lookup
    * Secret with arn1, version V1, labels as L1 and L2 is loaded as 4 entries
    * arn1 -> secret1
    * arn1:v1 -> secret2
    * arn1:l1 -> secret3
    * arn1:l2 -> secret4
    */
    private void loadCache(AWSSecretResponse awsSecretResponse) {
        synchronized (cacheLockObject) {
            GetSecretValueResponse decryptedResponse;
            try {
                decryptedResponse = localStoreMap.decrypt(awsSecretResponse);
            } catch (SecretCryptoException e) {
                // This should never happen ideally
                logger.atError().kv("secret", awsSecretResponse.getArn()).cause(e).log("Unable to decrypt secret, "
                        + "skip loading in cache");
                return;
            }
            putSecretInCache(decryptedResponse.arn(), decryptedResponse.versionId(), decryptedResponse);
        }
    }

    /*
    In case device is offline or device security service is unavailable, refreshSecretFromCloud will catch the
    exception, log the error and continue. The expectation is that the device may come online or device security
    service becomes available eventually. If refreshSecretFromCloud is being called in a loop then the loop should not
    exit entirely.
     */
    private void refreshSecretFromCloud(String arn, String versionStage) {
        String versionLabel = Utils.isEmpty(versionStage) ? LATEST_LABEL : versionStage;
        List<SecretConfiguration> configurations = getSecretConfiguration();
        boolean isSecretLabelConfigured = configurations.stream().anyMatch(
                (secret) -> secret.getArn().contains(arn) && secret.getLabels().contains(versionStage));
        // If the requested secret is not  configured, then do not download.
        if (!Utils.isEmpty(versionStage) && !isSecretLabelConfigured) {
            logger.atWarn().kv("secret", arn).kv("versionStage", versionStage).log("Not downloading the secret from "
                    + "cloud as it is not configured.");
            return;
        }
        GetSecretValueRequest request =
                GetSecretValueRequest.builder().secretId(arn).versionStage(versionLabel).build();
        try {
            GetSecretValueResponse response = secretClient.getSecret(request);
            logger.atDebug().kv("secret", arn).kv("versionStage", versionStage).log("Downloaded secret from cloud");
            localStoreMap.updateWithSecret(response, getSecretConfiguration());
            /*
            Always update the in-memory cache as saving to disk may fail due to a slow TPM but that should not fail
            a get secret IPC request
             */
            this.nameToArnMap.put(response.name(), response.arn());
            this.putSecretInCache(response);
        } catch (SecretManagerException e) {
            logger.atError().kv("secret", arn).kv("versionStage", versionStage).cause(e)
                    .log("Unable to refresh secret from cloud. Local store will not be updated");
        }
    }

    private void putSecretInCache(String secretArn, String versionId, GetSecretValueResponse secret) {
        cache.put(secretArn, secret);
        cache.put(secretArn + versionId, secret);
        for (String label : secret.versionStages()) {
            cache.put(secretArn + label, secret);
        }
    }

    private void putSecretInCache(GetSecretValueResponse secret) {
        putSecretInCache(secret.arn(), secret.versionId(), secret);
    }

    private GetSecretValueResponse getSecretFromCache(String secretId, String arn, String versionId,
                                                      String versionStage) throws GetSecretException {
        if (!Utils.isEmpty(versionId)) {
            if (!isSecretPresentInCache(arn + versionId)) {
                String errorStr = "Version Id " + versionId + " not found for secret " + secretId;
                logger.atError().kv("secretId", secretId).log(errorStr);
                throw new GetSecretException(404, errorStr);
            }
            return cache.get(arn + versionId);
        }

        if (!Utils.isEmpty(versionStage)) {
            if (!isSecretPresentInCache(arn + versionStage)) {
                String errorStr = "Version stage " + versionStage + " not found for secret " + secretId;
                logger.atError().kv("secretId", secretId).log(errorStr);
                throw new GetSecretException(404, errorStr);
            }
            return cache.get(arn + versionStage);
        }
        // If none of the label and version are specified then return LATEST_LABEL
        if (!isSecretPresentInCache((arn + LATEST_LABEL))) {
            logger.atError().kv("secretId", secretId).log(secretNotFoundErr);
            throw new GetSecretException(404, secretNotFoundErr + secretId);
        }
        return cache.get(arn + LATEST_LABEL);
    }

    private GetSecretValueResponse getSecret(String secretId, String versionId, String versionStage,
                                             boolean refreshSecret) throws GetSecretException {
        logger.atDebug().kv("secretId", secretId).kv("versionId", versionId).kv("versionStage", versionStage)
                .log("get-secret");

        // Both are optional
        if (!Utils.isEmpty(versionId) && !Utils.isEmpty(versionStage)) {
            logger.atError().kv("secretId", secretId).kv("versionId", versionId).kv("versionStage", versionStage)
                    .log("Both secret version and id are set");
            throw new GetSecretException(400, "Both versionId and Stage are set in the request");
        }

        /*
        If refresh is set to true, try fetching the secret from cloud. This will update the local store and cache as
        well. Refresh secrets by label only. If refreshing the secret fails for any reason, we fall back to local
        store.
         */
        String arn = validateSecretId(secretId);
        try {
            if (refreshSecret && Utils.isEmpty(versionId)) {
                refreshSecretFromCloud(arn, versionStage);
            }
            return getSecretFromCache(secretId, arn, versionId, versionStage);
        } catch (GetSecretException ex) {
            if (ex.getStatus() == 404 && Utils.isEmpty(versionId)) {
                // If secret is not found in the cache, then try to fetch latest one from the cloud
                logger.atDebug().kv("secretId", secretId).kv("label", versionStage).kv("version", versionId)
                        .log("Secret not found on disk. Trying to fetch from cloud");
                refreshSecretFromCloud(arn, versionStage);
            } else {
                throw ex;
            }
        }
        return getSecretFromCache(secretId, arn, versionId, versionStage);
    }

    /**
     * Get v1 style secret, to support lambdas using v1 SDK to get secrets.
     * @param request       v1 sdk request from lambda to get secret
     * @return secret       v1 sdk response containing secret and metadata
     * @throws GetSecretException    when there is any issue accessing secret
     */
    public com.aws.greengrass.secretmanager.model.v1.GetSecretValueResult
        getSecret(com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest request) throws GetSecretException {
        GetSecretValueResponse secretResponse =
                getSecret(request.getSecretId(), request.getVersionId(), request.getVersionStage(), false);
            return translateModeltov1(secretResponse);
    }

    /**
     * Get a secret for IPC. Secrets are stored in memory and only loaded from disk on reload or when synced from
     * cloud.
     * @param request IPC request from kernel to get secret
     * @return secret IPC response containing secret and metadata
     * @throws GetSecretException when there is any issue accessing secret
     */
    public software.amazon.awssdk.aws.greengrass.model.GetSecretValueResponse
    getSecret(software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest request)
            throws GetSecretException {
        boolean refreshField = false;
        boolean isRefreshFieldSupported = Arrays.stream(request.getClass().getDeclaredFields())
                .anyMatch(((x) -> x.getName().equals(IPC_REQUEST_REFRESH_FIELD)));
        if (isRefreshFieldSupported) {
            refreshField = Coerce.toBoolean(request.isRefresh());
        }
        GetSecretValueResponse secretResponse =
                getSecret(request.getSecretId(), request.getVersionId(), request.getVersionStage(), refreshField);
            return translateModeltoIpc(secretResponse);
    }

    private boolean isSecretPresentInCache(String arn) {
        return cache.containsKey(arn);
    }

    /**
     * Return secret arn given secretId. If secret name is provided, then return its mapped arn.
     *
     * @param secretId secret name or arn
     * @return secret arn
     * @throws GetSecretException when secret is not found
     */
    public String validateSecretId(String secretId) throws GetSecretException {
        if (Utils.isEmpty(secretId)) {
            throw new GetSecretException(400, "SecretId absent in the request");
        }
        String arn = getArnFromCache(secretId);
        if (!isSecretPresentInCache(arn)) {
            try {
                reloadCache();
            } catch (SecretManagerException e) {
                // TODO: Improve return code where device is offline and SM is unable to load cache from disk
                logger.atWarn().setCause(e).log("Unable to load secrets from cache");
            }
        }
        return arn;
    }

    private boolean isSecretIdArn(final String secretId) {
        return Pattern.matches(VALID_SECRET_ARN_PATTERN, secretId);
    }

    private boolean doesSecretNameMatchWithConfiguredArn(String secretName, String secretArn) {
        String regex = ".*:secret:" + Pattern.quote(secretName) + "-[A-Za-z0-9]{6}(?::[A-Za-z0-9/_+=.@-]+)?$";
        Pattern pattern = Pattern.compile(regex);
        return pattern.matcher(secretArn).matches();
    }

    // TODO: add validation for labels
    private String getArnFromCache(final String secretId) throws GetSecretException {
        String arn = secretId;
        if (!isSecretIdArn(secretId)) {
            arn = nameToArnMap.get(secretId);
        }

        /*
        In case device was offline or security service was unavailable during the initial sync, nameToArnMap
        is empty and if GetSecret IPC is invoked using a secret name with refresh, we fail.
        Fix: try to lookup the secret ARN using the requested secret name in configured secrets.
         */
        if (Utils.isEmpty(arn)) {
            List<SecretConfiguration> configurations = getSecretConfiguration();
            Optional<SecretConfiguration> matchedSecretConfig = configurations.stream()
                    .filter(config -> doesSecretNameMatchWithConfiguredArn(secretId, config.getArn()))
                    .findFirst();
            if (matchedSecretConfig.isPresent()) {
                return matchedSecretConfig.get().getArn();
            }
            throw new GetSecretException(404, secretNotConfiguredErr + secretId);
        }
        return arn;
    }

    private com.aws.greengrass.secretmanager.model.v1.GetSecretValueResult
        translateModeltov1(GetSecretValueResponse response) {
        if (response.secretBinary() != null) {
            return com.aws.greengrass.secretmanager.model.v1.GetSecretValueResult
                    .builder()
                    .arn(response.arn())
                    .name(response.name())
                    .secretString(null)
                    .secretBinary(ByteBuffer.wrap(response.secretBinary().asByteArray()))
                    .versionId(response.versionId())
                    .versionStages(response.versionStages())
                    .createdDate(Date.from(response.createdDate()))
                    .build();
        }
        return com.aws.greengrass.secretmanager.model.v1.GetSecretValueResult
                .builder()
                .arn(response.arn())
                .name(response.name())
                .secretString(response.secretString())
                .secretBinary(null)
                .versionId(response.versionId())
                .versionStages(response.versionStages())
                .createdDate(Date.from(response.createdDate()))
                .build();
    }

    private software.amazon.awssdk.aws.greengrass.model.GetSecretValueResponse translateModeltoIpc(
            GetSecretValueResponse response) {
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueResponse ipcResponse =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueResponse();
        SecretValue secretValue = new SecretValue();
        if (response.secretBinary() != null) {
            secretValue.setSecretBinary(response.secretBinary().asByteArray());
        } else {
            secretValue.setSecretString(response.secretString());
        }
        ipcResponse.setSecretId(response.arn());
        ipcResponse.setSecretValue(secretValue);
        ipcResponse.setVersionId(response.versionId());
        ipcResponse.setVersionStage(response.versionStages());
        return ipcResponse;
    }
}
