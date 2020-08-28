package com.aws.iot.greengrass.secretmanager;

import com.aws.iot.evergreen.ipc.services.secret.SecretResponseStatus;
import com.aws.iot.evergreen.logging.api.Logger;
import com.aws.iot.evergreen.logging.impl.LogManager;
import com.aws.iot.evergreen.util.Utils;
import com.aws.iot.greengrass.secretmanager.crypto.Crypter;
import com.aws.iot.greengrass.secretmanager.crypto.KeyChain;
import com.aws.iot.greengrass.secretmanager.crypto.MasterKey;
import com.aws.iot.greengrass.secretmanager.crypto.PemFile;
import com.aws.iot.greengrass.secretmanager.crypto.RSAMasterKey;
import com.aws.iot.greengrass.secretmanager.exception.SecretCryptoException;
import com.aws.iot.greengrass.secretmanager.exception.SecretManagerException;
import com.aws.iot.greengrass.secretmanager.kernel.KernelClient;
import com.aws.iot.greengrass.secretmanager.model.AWSSecretResponse;
import com.aws.iot.greengrass.secretmanager.model.SecretConfiguration;
import com.aws.iot.greengrass.secretmanager.model.SecretDocument;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
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
            "arn:aws:secretsmanager:[a-z0-9\\-]+:[0-9]{12}:secret:([a-zA-Z0-9\\\\]+/)*"
                    + "[a-zA-Z0-9/_+=,.@\\-]+-[a-zA-Z0-9]+";
    private final Logger logger = LogManager.getLogger(SecretManager.class);
    // Cache which holds aws secrets result
    private ConcurrentHashMap<String, GetSecretValueResponse> cache = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, String> nametoArnMap = new ConcurrentHashMap<>();

    private final AWSSecretClient secretClient;
    private final SecretDao<SecretDocument> secretDao;
    private final Crypter crypter;

    /**
     * Constructor.
     * @param secretClient client for aws secrets.
     * @param kernelClient client for kernel
     * @param dao          dao for persistent store.
     * @throws SecretCryptoException when unable to initialize.
     */
    @Inject
    SecretManager(AWSSecretClient secretClient, KernelClient kernelClient, FileSecretDao dao)
            throws SecretCryptoException {
        this.secretDao = dao;
        this.secretClient = secretClient;
        String keyPath = kernelClient.getPrivateKeyPath();
        String certPath = kernelClient.getCertPath();

        PublicKey publicKey = PemFile.generatePublicKeyFromCert(certPath);
        PrivateKey privateKey = PemFile.generatePrivateKey(keyPath);

        MasterKey masterKey = RSAMasterKey.createInstance(publicKey, privateKey);
        KeyChain keyChain = new KeyChain();
        keyChain.addMasterKey(masterKey);
        this.crypter = new Crypter(keyChain);
    }

    /**
     * Constructor for unit testing.
     * @param secretClient client for aws secrets.
     * @param crypter      crypter for secrets.
     * @param dao          dao for persistent store.
     */
    SecretManager(AWSSecretClient secretClient, Crypter crypter, FileSecretDao dao) {
        this.secretDao = dao;
        this.secretClient = secretClient;
        this.crypter = crypter;
    }

    /**
     * Syncs secret manager by downloading secrets from cloud and then stores it locally.
     * This is used when configuration changes and secrets have to be re downloaded.
     * @param configuredSecrets List of secrets that are to be downloaded
     * @throws SecretManagerException when there are issues reading/writing to disk
     */
    public void syncFromCloud(List<SecretConfiguration> configuredSecrets) throws SecretManagerException {
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
                    GetSecretValueResponse result = secretClient.getSecret(request);
                    // Save the secrets to local store for offline access
                    byte[] encryptedSecret = crypter.encrypt(result.secretString().getBytes(StandardCharsets.UTF_8),
                            result.arn());
                    // reuse all fields except the secret value, replace secret value with encrypted value
                    AWSSecretResponse encryptedResult = AWSSecretResponse.builder()
                            .encryptedSecretString(Base64.getEncoder().encodeToString(encryptedSecret))
                            .name(result.name())
                            .arn(result.arn())
                            .createdDate(result.createdDate().toEpochMilli())
                            .versionId(result.versionId())
                            .versionStages(result.versionStages())
                            .build();
                    downloadedSecrets.add(encryptedResult);
                } catch (Throwable e) {
                    logger.atWarn().kv("Secret ", secretArn).log("Could not fetch secret from cloud", e);
                    continue;
                }
            }
        }
        secretDao.saveAll(SecretDocument.builder().secrets(downloadedSecrets).build());
        // Once the secrets are finished downloading, load it locally
        loadSecretsFromLocalStore();
    }

    /**
     * load the secrets from a local store. This is used across restarts to load secrets from store.
     * @throws SecretManagerException when there are issues reading from disk
     */
    public void loadSecretsFromLocalStore() throws SecretManagerException {
        // read the db
        List<AWSSecretResponse> secrets = secretDao.getAll().getSecrets();
        for (AWSSecretResponse secretResult : secrets) {
            nametoArnMap.put(secretResult.getName(), secretResult.getArn());
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
    private void loadCache(AWSSecretResponse awsSecretResponse) throws SecretManagerException {
        GetSecretValueResponse decryptedResponse = null;
        try {
            byte[] decryptedSecret = crypter.decrypt(
                    Base64.getDecoder().decode(awsSecretResponse.getEncryptedSecretString()),
                    awsSecretResponse.getArn());
            // reuse all fields except the secret value, replace that with decrypted value
            decryptedResponse = GetSecretValueResponse.builder()
                    .secretString(new String(decryptedSecret, StandardCharsets.UTF_8))
                    .name(awsSecretResponse.getName())
                    .arn(awsSecretResponse.getArn())
                    .createdDate(Instant.ofEpochMilli(awsSecretResponse.getCreatedDate()))
                    .versionId(awsSecretResponse.getVersionId())
                    .versionStages(awsSecretResponse.getVersionStages())
                    .build();
        } catch (SecretCryptoException e) {
            // This should never happen ideally
            logger.atError().kv("secret",
                    awsSecretResponse.getArn()).cause(e).log("Unable to decrypt secret, skip loading in cache");
            throw new SecretManagerException("Cannot load secret from disk");
        }
        String secretArn = decryptedResponse.arn();
        cache.put(secretArn, decryptedResponse);
        cache.put(secretArn + decryptedResponse.versionId(), decryptedResponse);
        // load all labels attached with this version of secret
        for (String label : decryptedResponse.versionStages()) {
            cache.put(secretArn + label, decryptedResponse);
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
     * Get a secret. Secrets are stored in memory and only loaded from disk on reload or when synced from cloud.
     * @param request IPC request from kernel to get secret
     * @return secret IPC response containing secret and metadata
     */
    public com.aws.iot.evergreen.ipc.services.secret.GetSecretValueResult
        getSecret(com.aws.iot.evergreen.ipc.services.secret.GetSecretValueRequest request) {

        // TODO: Add support for secret binary
        // TODO: Add support for v1 IPC
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
