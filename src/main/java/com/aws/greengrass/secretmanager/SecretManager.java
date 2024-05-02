/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager;

import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import com.aws.greengrass.secretmanager.crypto.Crypter;
import com.aws.greengrass.secretmanager.crypto.KeyChain;
import com.aws.greengrass.secretmanager.crypto.MasterKey;
import com.aws.greengrass.secretmanager.crypto.RSAMasterKey;
import com.aws.greengrass.secretmanager.exception.SecretCryptoException;
import com.aws.greengrass.secretmanager.exception.SecretManagerException;
import com.aws.greengrass.secretmanager.exception.v1.GetSecretException;
import com.aws.greengrass.secretmanager.model.AWSSecretResponse;
import com.aws.greengrass.secretmanager.model.SecretConfiguration;
import com.aws.greengrass.secretmanager.model.SecretDocument;
import com.aws.greengrass.secretmanager.store.FileSecretStore;
import com.aws.greengrass.secretmanager.store.SecretStore;
import com.aws.greengrass.security.SecurityService;
import com.aws.greengrass.security.exceptions.ServiceUnavailableException;
import com.aws.greengrass.util.Coerce;
import com.aws.greengrass.util.RetryUtils;
import com.aws.greengrass.util.Utils;
import software.amazon.awssdk.aws.greengrass.model.SecretValue;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.regex.Pattern;
import javax.annotation.Nullable;
import javax.inject.Inject;

/**
 * Class which holds the business logic for secret management. This class always holds a copy of
 * actual AWS secrets response in memory to serve requests. Since v1 and v2 IPC models are different
 * this class directly translates the AWS responses in memory to v1/v2 models as part of IPC requests.
 * Secrets are stored encrypted for availability across restarts. In memory copy is always plain text.
 */
public class SecretManager {
    private static final String LATEST_LABEL = "AWSCURRENT";
    public static final String VALID_SECRET_ARN_PATTERN =
            "arn:([^:]+):secretsmanager:[a-z0-9\\-]+:[0-9]{12}:secret:([a-zA-Z0-9\\\\]+/)*"
                    + "[a-zA-Z0-9/_+=,.@\\-]+(-[a-zA-Z0-9]+)?";
    private static final String secretNotFoundErr = "Secret not found ";
    private final Logger logger = LogManager.getLogger(SecretManager.class);
    // Cache which holds aws secrets result
    private final ConcurrentHashMap<String, GetSecretValueResponse> cache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> nameToArnMap = new ConcurrentHashMap<>();

    private final AWSSecretClient secretClient;
    private final SecretStore<SecretDocument, AWSSecretResponse> secretStore;
    @Nullable
    private Crypter crypter;
    private final Result<SecretCryptoException> initialized = new Result<>();

    /**
     * Constructor.
     * @param secretClient client for aws secrets.
     * @param securityService security service.
     * @param dao          dao for persistent store.
     */
    @Inject
    SecretManager(AWSSecretClient secretClient, SecurityService securityService, FileSecretStore dao,
                  ExecutorService executor) {
        this.secretStore = dao;
        this.secretClient = secretClient;

        executor.execute(() -> loadCrypter(securityService));
    }

    private void loadCrypter(SecurityService securityService) {
        try {
            URI privateKeyUri = securityService.getDeviceIdentityPrivateKeyURI();
            URI certUri = securityService.getDeviceIdentityCertificateURI();
            KeyPair kp = RetryUtils.runWithRetry(RetryUtils.RetryConfig.builder().maxAttempt(Integer.MAX_VALUE)
                            .retryableExceptions(Collections.singletonList(ServiceUnavailableException.class)).build(),
                    () -> securityService.getKeyPair(privateKeyUri, certUri), "get-keypair",
                    logger);
            MasterKey masterKey = RSAMasterKey.createInstance(kp.getPublic(), kp.getPrivate());
            KeyChain keyChain = new KeyChain();
            keyChain.addMasterKey(masterKey);
            this.crypter = new Crypter(keyChain);
            this.initialized.set(null);
        } catch (SecretCryptoException e) {
            this.initialized.set(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            this.initialized.set(new SecretCryptoException(e));
        }
    }

    /**
     * Constructor for unit testing.
     * @param secretClient client for aws secrets.
     * @param crypter      crypter for secrets.
     * @param dao          dao for persistent store.
     */
    SecretManager(AWSSecretClient secretClient, Crypter crypter, FileSecretStore dao) {
        this.secretStore = dao;
        this.secretClient = secretClient;
        this.crypter = crypter;
        this.initialized.set(null);
    }

    /**
     * Syncs secret manager by downloading secrets from cloud and then stores it locally.
     * This is used when configuration changes and secrets have to be re downloaded.
     * @param configuredSecrets List of secrets that are to be downloaded
     * @throws SecretManagerException when there are issues reading/writing to disk
     * @throws InterruptedException if thread is interrupted while running
     */
    public void syncFromCloud(List<SecretConfiguration> configuredSecrets)
            throws SecretManagerException, InterruptedException {
        logger.atDebug("sync-secret-from-cloud").log();
        try {
            waitForInitialization();
        } catch (SecretCryptoException e) {
            throw new SecretManagerException(e);
        }
        List<AWSSecretResponse> downloadedSecrets = new ArrayList<>();
        for (SecretConfiguration secretConfig : configuredSecrets) {
            String secretArn = secretConfig.getArn();
            if (!Pattern.matches(VALID_SECRET_ARN_PATTERN, secretArn)) {
                logger.atWarn().kv("Secret ", secretArn).log("Skipping invalid secret arn configured");
                continue;
            }
            // Labels are optional
            Set<String> labelsToDownload = new HashSet<>();
            if (!Utils.isEmpty(secretConfig.getLabels())) {
                labelsToDownload.addAll(secretConfig.getLabels());
            }
            labelsToDownload.add(LATEST_LABEL);
            for (String label : labelsToDownload) {
                GetSecretValueRequest request = GetSecretValueRequest.builder().secretId(secretArn)
                        .versionStage(label).build();
                try {
                    AWSSecretResponse encryptedResult = fetchAndEncryptAWSResponse(request);
                    downloadedSecrets.add(encryptedResult);
                } catch (IOException | SdkClientException e) {
                    AWSSecretResponse secretFromDao = secretStore.get(secretArn, label);
                    if (secretFromDao != null) {
                        logger.atWarn().kv("secret", secretArn).kv("label", label)
                                .log("Could not sync secret from cloud, but we have a local version which may work");
                        // We couldn't sync it from the cloud, try loading it from local copy
                        try {
                            // Ensure that we're able to decrypt it. If we are unable to decrypt it
                            // then we have no more fallbacks and the customer needs to fix the issue.
                            decrypt(secretFromDao);
                            downloadedSecrets.add(secretFromDao);
                            logger.atDebug().kv("secret", secretArn).kv("label", label)
                                    .log("Secret configuration is not changed. Loaded from local store");
                        } catch (SecretCryptoException ex) {
                            e.addSuppressed(ex);
                            throw new SecretManagerException(
                                    String.format("Could not download secret %s with label %s from cloud, you can "
                                            + "attempt a re-fetch by redeploying secret manager", secretArn, label),
                                    e);
                        }
                    } else {
                        throw new SecretManagerException(
                                String.format("Could not download secret %s with label %s from cloud, you can "
                                        + "attempt a re-fetch by redeploying secret manager", secretArn, label),
                                e);
                    }
                } catch (Exception e) {
                    throw new SecretManagerException(e);
                }
            }
        }
        secretStore.saveAll(SecretDocument.builder().secrets(downloadedSecrets).build());
        // Once the secrets are finished downloading, load it locally
        loadSecretsFromLocalStore();
    }

    private AWSSecretResponse fetchAndEncryptAWSResponse(GetSecretValueRequest request)
            throws SecretCryptoException, SecretManagerException, IOException {
        GetSecretValueResponse result = secretClient.getSecret(request);
        // Save the secrets to local store for offline access
        String encodedSecretString = null;
        if (result.secretString() != null) {
            byte[] encryptedSecretString = crypter.encrypt(
                    result.secretString().getBytes(StandardCharsets.UTF_8),
                    result.arn());
            encodedSecretString = Base64.getEncoder().encodeToString(encryptedSecretString);
        }
        String encodedSecretBinary = null;
        if (result.secretBinary() != null) {
            byte[] encryptedSecretBinary = crypter.encrypt(
                    result.secretBinary().asByteArray(),
                    result.arn());
            encodedSecretBinary = Base64.getEncoder().encodeToString(encryptedSecretBinary);
        }
         // reuse all fields except the secret value, replace secret value with encrypted value
         return AWSSecretResponse.builder()
                .encryptedSecretString(encodedSecretString)
                .encryptedSecretBinary(encodedSecretBinary)
                .name(result.name())
                .arn(result.arn())
                .createdDate(result.createdDate().toEpochMilli())
                .versionId(result.versionId())
                .versionStages(result.versionStages())
                .build();
    }

    /**
     * Wait until interrupted for the crypter to be initialized.
     *
     * @throws SecretCryptoException if initialization failed
     * @throws InterruptedException  if the thread is interrupted while waiting
     */
    void waitForInitialization() throws SecretCryptoException, InterruptedException {
        synchronized (initialized) {
            while (!initialized.isSet()) {
                initialized.wait();
            }
        }
        if (initialized.isSet()) {
            if (initialized.getValue() != null) {
                throw initialized.getValue();
            }
        }
    }

    /**
     * load the secrets from a local store. This is used across restarts to load secrets from store.
     * @throws SecretManagerException when there are issues reading from disk
     */
    public void loadSecretsFromLocalStore() throws SecretManagerException {
        logger.atDebug("load-secret-local-store").log();
        // read the db
        List<AWSSecretResponse> secrets = secretStore.getAll().getSecrets();
        nameToArnMap.clear();
        cache.clear();
        if (!Utils.isEmpty(secrets)) {
            for (AWSSecretResponse secretResult : secrets) {
                nameToArnMap.put(secretResult.getName(), secretResult.getArn());
                loadCache(secretResult);
            }
        }
    }

    private GetSecretValueResponse decrypt(AWSSecretResponse awsSecretResponse) throws SecretCryptoException {
        String decryptedSecretString = null;
        if (awsSecretResponse.getEncryptedSecretString() != null) {
            byte[] decryptedSecret = crypter.decrypt(
                    Base64.getDecoder().decode(awsSecretResponse.getEncryptedSecretString()),
                    awsSecretResponse.getArn());
            decryptedSecretString = new String(decryptedSecret, StandardCharsets.UTF_8);
        }

        SdkBytes decryptedSecretBinary = null;
        if (awsSecretResponse.getEncryptedSecretBinary() != null) {
            byte[] decryptedSecret = crypter.decrypt(
                    Base64.getDecoder().decode(awsSecretResponse.getEncryptedSecretBinary()),
                    awsSecretResponse.getArn());
            decryptedSecretBinary = SdkBytes.fromByteArray(decryptedSecret);
        }

        return GetSecretValueResponse.builder()
                .secretString(decryptedSecretString)
                .secretBinary(decryptedSecretBinary)
                .name(awsSecretResponse.getName())
                .arn(awsSecretResponse.getArn())
                .createdDate(Instant.ofEpochMilli(awsSecretResponse.getCreatedDate()))
                .versionId(awsSecretResponse.getVersionId())
                .versionStages(awsSecretResponse.getVersionStages())
                .build();
    }

    /*
    * Cache holds multiple references of the secret with different keys for fast lookup
    * Secret with arn1, version V1, labels as L1 and L2 is loaded as 4 entries
    * arn1 -> secret1
    * arn1:v1 -> secret2
    * arn1:l1 -> secret3
    * arn1:l2 -> secret4
    */
    private void loadCache(AWSSecretResponse awsSecretResponse)
            throws SecretManagerException {
        GetSecretValueResponse decryptedResponse = null;
        try {
            decryptedResponse = decrypt(awsSecretResponse);
        } catch (SecretCryptoException e) {
            // This should never happen ideally
            logger.atError().kv("secret",
                    awsSecretResponse.getArn()).cause(e).log("Unable to decrypt secret, skip loading in cache");
            throw new SecretManagerException("Cannot load secret from disk", e);
        }
        String secretArn = decryptedResponse.arn();
        cache.put(secretArn, decryptedResponse);
        cache.put(secretArn + decryptedResponse.versionId(), decryptedResponse);
        // load all labels attached with this version of secret
        for (String label : decryptedResponse.versionStages()) {
            cache.put(secretArn + label, decryptedResponse);
        }
    }

    private void refreshSecretFromCloud(String arn, String versionStage) {
        // TODO: Make this a non-blocking op.
        String versionLabel = Utils.isEmpty(versionStage) ? LATEST_LABEL : versionStage;
        GetSecretValueRequest request =
                GetSecretValueRequest.builder().secretId(arn).versionStage(versionLabel).build();
        try {
            AWSSecretResponse encryptedResult = fetchAndEncryptAWSResponse(request);
            secretStore.save(encryptedResult);
            loadSecretsFromLocalStore();
        } catch (SecretCryptoException | SecretManagerException | IOException e) {
            logger.atError().cause(e).log("Unable to refresh secret from cloud.");
        }
    }

    private GetSecretValueResponse getSecretFromCache(String secretId, String arn, String versionId,
                                                      String versionStage) throws GetSecretException {
        if (!Utils.isEmpty(versionId)) {
            if (!cache.containsKey(arn + versionId)) {
                String errorStr = "Version Id " + versionId + " not found for secret " + secretId;
                logger.atError().kv("secretId", secretId).log(errorStr);
                throw new GetSecretException(404, errorStr);
            }
            return cache.get(arn + versionId);
        }

        if (!Utils.isEmpty(versionStage)) {
            if (!cache.containsKey(arn + versionStage)) {
                String errorStr = "Version stage " + versionStage + " not found for secret " + secretId;
                logger.atError().kv("secretId", secretId).log(errorStr);
                throw new GetSecretException(404, errorStr);
            }
            return cache.get(arn + versionStage);
        }
        // If none of the label and version are specified then return LATEST_LABEL
        if (!cache.containsKey((arn + LATEST_LABEL))) {
            logger.atError().kv("secretId", secretId).log(secretNotFoundErr);
            throw new GetSecretException(404, secretNotFoundErr + secretId);
        }
        return cache.get(arn + LATEST_LABEL);
    }

    private GetSecretValueResponse getSecret(String secretId, String versionId, String versionStage,
                                             boolean refreshSecret) throws GetSecretException {
        logger.atDebug().kv("secretId", secretId).kv("versionId", versionId).kv("versionStage", versionStage)
                .log("get-secret");
        String arn = validateSecretId(secretId);

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
        if (refreshSecret && Utils.isEmpty(versionId)) {
            refreshSecretFromCloud(arn, versionStage);
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
        GetSecretValueResponse secretResponse =
                getSecret(request.getSecretId(), request.getVersionId(), request.getVersionStage(),
                        Coerce.toBoolean(request.isRefresh()));
            return translateModeltoIpc(secretResponse);
    }

    /**
     * Return secret arn given secretId. If secret name is provided, then return its mapped arn.
     *
     * @param secretId secret name or arn
     * @return secret arn
     * @throws GetSecretException when secret is not found
     */
    public String validateSecretId(String secretId) throws GetSecretException {
        String arn = secretId;
        if (Utils.isEmpty(secretId)) {
            throw new GetSecretException(400, "SecretId absent in the request");
        }
        // normalize name to arn
        if (!Pattern.matches(VALID_SECRET_ARN_PATTERN, secretId)) {
            arn = nameToArnMap.get(secretId);
            if (arn == null) {
                throw new GetSecretException(404, secretNotFoundErr + secretId);
            }
        }

        // We cannot just return the value, as same arn can have multiple labels associated to it.
        if (!cache.containsKey(arn)) {
            throw new GetSecretException(404, secretNotFoundErr + secretId);
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
