package com.aws.iot.greengrass.secretmanager;

import com.aws.iot.evergreen.ipc.services.secret.SecretResponseStatus;
import com.aws.iot.evergreen.logging.api.Logger;
import com.aws.iot.evergreen.logging.impl.LogManager;
import com.aws.iot.evergreen.util.Utils;
import com.aws.iot.greengrass.secretmanager.model.SecretConfiguration;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import javax.inject.Inject;

public class SecretManager {
    private static final String LATEST_LABEL = "AWSCURRENT";
    public static final String VALID_SECRET_ARN_PATTERN =
            "arn:aws:secretsmanager:[a-z0-9\\-]+:[0-9]{12}:secret:([a-zA-Z0-9\\\\]+/)*"
                    + "[a-zA-Z0-9/_+=,.@\\-]+-[a-zA-Z0-9]+";
    private final Logger logger = LogManager.getLogger(SecretManager.class);
    // Cache which holds aws secrets result
    private Map<String, GetSecretValueResponse> cache = new HashMap<>();
    private Map<String, String> nametoArnMap = new HashMap<>();

    private final AWSClient secretClient;
    private final SecretDao secretDao;

    @Inject
    SecretManager(AWSClient secretClient, MemorySecretDao dao) {
        this.secretDao = dao;
        this.secretClient = secretClient;
    }

    /**
     * Syncs secret manager by downloading secrets from cloud and then stores it locally.
     * This is used when configuration changes and secrets are refetched.
     * @param configuredSecrets List of secrets that are to be downloaded
     */
    public void syncFromCloud(List<SecretConfiguration> configuredSecrets) {
        for (SecretConfiguration secretConfig: configuredSecrets) {
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
            for (String label: labelsToDownload) {
                GetSecretValueRequest request = GetSecretValueRequest.builder().secretId(secretArn)
                        .versionStage(label).build();
                try {
                    GetSecretValueResponse result = secretClient.getSecret(request);
                    // Save the secrets to local store for offline access
                    // TODO: Move to persistent storage
                    // TODO: Support encrypted secrets
                    secretDao.save(secretArn, result);
                } catch (Throwable e) {
                    logger.atWarn().kv("Secret ", secretArn).log("Could not fetch secret from cloud", e);
                    continue;
                }
            }
        }

        // Once the secrets are finished downloading, load it locally
        loadSecretsFromLocalStore();
    }

    /**
     * load the secrets from a local store. This is used across restarts to load secrets from store.
     */
    public void loadSecretsFromLocalStore() {
        // read the db
        List<GetSecretValueResponse> secrets = secretDao.getAll();
        for (GetSecretValueResponse secretResult: secrets) {
            nametoArnMap.put(secretResult.name(), secretResult.arn());
            loadCache(secretResult);
        }
    }

    /*
    * Cache holds multiple references of the secret with different keys for fast lookup
    * Secret with arn1, version V1, labels as L1 and L2 is loaded as 4 entries
    * arn1 -> secret
    * arn1:v1 -> secret
    * arn1:l1 -> secret
    * arn1:l2 -> secret
    */
    private void loadCache(GetSecretValueResponse getSecretValueResponse) {
        String secretArn = getSecretValueResponse.arn();
        cache.put(secretArn, getSecretValueResponse);
        cache.put(secretArn + getSecretValueResponse.versionId(), getSecretValueResponse);
        // load all labels attached with this version of secret
        for (String label: getSecretValueResponse.versionStages()) {
            cache.put(secretArn + label, getSecretValueResponse);
        }
    }

    private com.aws.iot.evergreen.ipc.services.secret.GetSecretValueResult
        translateModeltoIpc(GetSecretValueResponse response) {
        return com.aws.iot.evergreen.ipc.services.secret.GetSecretValueResult
                .builder()
                .secretId(response.arn())
                .secretString(response.secretString())
                .versionId(response.versionId())
                .versionStages(response.versionStages())
                .responseStatus(SecretResponseStatus.Success)
                .build();
    }

    /**
     * get a secret.
     * @param request IPC request from kernel to get secret
     * @return secret IPC response containing secret and metadata
     */
    public com.aws.iot.evergreen.ipc.services.secret.GetSecretValueResult
        getSecret(com.aws.iot.evergreen.ipc.services.secret.GetSecretValueRequest request) {

        // TODO: Add support for secret binary
        // TODO: ADd support for v1 IPC
        String secretId = request.getSecretId();
        String arn = secretId;
        if (Utils.isEmpty(secretId)) {
            return buildErrorResponse(SecretResponseStatus.InvalidRequest, "SecretId absent in the request");
        }
        // normalize name to arn
        if (!Pattern.matches(VALID_SECRET_ARN_PATTERN, secretId)) {
            if (!nametoArnMap.containsKey(secretId)) {
                return buildErrorResponse(SecretResponseStatus.InvalidRequest, "Secret not found " + secretId);
            }
            arn = nametoArnMap.get(secretId);
        }

        // We cannot just return the value, as same arn can have multiple labels associated to it.
        if (!cache.containsKey(arn)) {
            return buildErrorResponse(SecretResponseStatus.InvalidRequest, "Secret not found " + secretId);
        }

        // Both are optional
        String versionId = request.getVersionId();
        String versionStage = request.getVersionStage();
        if (!Utils.isEmpty(versionId) && !Utils.isEmpty(versionStage)) {
            return buildErrorResponse(SecretResponseStatus.InvalidRequest,
                    "Both versionId and Stage are set in the request");
        }

        if (!Utils.isEmpty(versionId)) {
            if (!cache.containsKey(arn + versionId)) {
                String errorStr = "Version Id " + versionId + " not found for secret " + secretId;
                return buildErrorResponse(SecretResponseStatus.InvalidRequest, errorStr);
            }
            return translateModeltoIpc(cache.get(arn + versionId));
        }

        if (!Utils.isEmpty(versionStage)) {
            if (!cache.containsKey(arn + versionStage)) {
                String errorStr = "Version stage " + versionStage + " not found for secret " + secretId;
                return buildErrorResponse(SecretResponseStatus.InvalidRequest, errorStr);
            }
            return translateModeltoIpc(cache.get(arn + versionStage));
        }
        // If none of the label and version are specified then return LATEST_LABEL
        if (!cache.containsKey((arn + LATEST_LABEL))) {
            return buildErrorResponse(SecretResponseStatus.InvalidRequest, "Secret not found " + secretId);
        }
        return translateModeltoIpc(cache.get(arn + LATEST_LABEL));
    }

    private com.aws.iot.evergreen.ipc.services.secret.GetSecretValueResult
        buildErrorResponse(SecretResponseStatus status, String error) {
        return com.aws.iot.evergreen.ipc.services.secret.GetSecretValueResult
                .builder()
                .responseStatus(status)
                .errorMessage(error)
                .build();
    }
}
