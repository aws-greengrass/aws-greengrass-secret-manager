package com.aws.greengrass.secretmanager;

import com.aws.greengrass.config.Node;
import com.aws.greengrass.deployment.DeviceConfiguration;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import com.aws.greengrass.secretmanager.crypto.Crypter;
import com.aws.greengrass.secretmanager.crypto.KeyChain;
import com.aws.greengrass.secretmanager.crypto.MasterKey;
import com.aws.greengrass.secretmanager.crypto.RSAMasterKey;
import com.aws.greengrass.secretmanager.exception.SecretCryptoException;
import com.aws.greengrass.secretmanager.exception.SecretManagerException;
import com.aws.greengrass.secretmanager.model.AWSSecretResponse;
import com.aws.greengrass.secretmanager.model.SecretConfiguration;
import com.aws.greengrass.secretmanager.model.SecretDocument;
import com.aws.greengrass.secretmanager.store.FileSecretStore;
import com.aws.greengrass.secretmanager.store.SecretStore;
import com.aws.greengrass.security.SecurityService;
import com.aws.greengrass.security.exceptions.ServiceUnavailableException;
import com.aws.greengrass.util.Coerce;
import com.aws.greengrass.util.LockFactory;
import com.aws.greengrass.util.LockScope;
import com.aws.greengrass.util.RetryUtils;
import com.aws.greengrass.util.Utils;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Lock;
import javax.inject.Inject;

import static com.aws.greengrass.deployment.DeviceConfiguration.DEVICE_PARAM_CERTIFICATE_FILE_PATH;
import static com.aws.greengrass.deployment.DeviceConfiguration.DEVICE_PARAM_PRIVATE_KEY_PATH;

public class LocalStoreMap {
    private final Logger logger = LogManager.getLogger(LocalStoreMap.class);
    private final ConcurrentHashMap<String, Labels> secrets;
    private final SecretStore<SecretDocument, AWSSecretResponse> secretStore;
    private final AtomicReference<Crypter> crypter = new AtomicReference<>();
    private final SecurityService securityService;

    private final Lock lock = LockFactory.newReentrantLock(this);
    private final Lock localStoreLock = LockFactory.newReentrantLock(this);

    @Inject
    LocalStoreMap(SecurityService securityService, FileSecretStore dao, DeviceConfiguration deviceConfiguration) {
        this.secretStore = dao;
        this.securityService = securityService;
        deviceConfiguration.onAnyChange(((whatHappened, node) -> {
            if (validUpdate(node, DEVICE_PARAM_CERTIFICATE_FILE_PATH) || validUpdate(node,
                    DEVICE_PARAM_PRIVATE_KEY_PATH)) {
                // TODO: Trigger downloading new secrets from cloud and encrypt them with the new creds.
                try (LockScope ls = LockScope.lock(lock)) {
                    crypter.set(null);
                }
            }
        }));
        this.secrets = new ConcurrentHashMap<>();
    }

    private boolean validUpdate(Node node, String key) {
        return node != null && node.childOf(key) && Utils.isNotEmpty(Coerce.toString(node));
    }

    protected Crypter getCrypter() throws SecretCryptoException {
        try (LockScope ls = LockScope.lock(lock)) {
            if (crypter.get() == null) {
                try {
                    loadCrypter();
                } catch (Exception e) {
                    throw new SecretCryptoException("Unable to load crypter", e);
                }
            }
            return crypter.get();
        }
    }

    private void loadCrypter() throws Exception {
        try {
            URI privateKeyUri = securityService.getDeviceIdentityPrivateKeyURI();
            URI certUri = securityService.getDeviceIdentityCertificateURI();
            KeyPair kp = RetryUtils.runWithRetry(
                    RetryUtils.RetryConfig.builder().maxRetryInterval(Duration.ofSeconds(30))
                            .initialRetryInterval(Duration.ofSeconds(10)).maxAttempt(10)
                            .retryableExceptions(Collections.singletonList(ServiceUnavailableException.class)).build(),
                    () -> securityService.getKeyPair(privateKeyUri, certUri), "get-keypair", logger);
            MasterKey masterKey = RSAMasterKey.createInstance(kp.getPublic(), kp.getPrivate());
            KeyChain keyChain = new KeyChain();
            keyChain.addMasterKey(masterKey);
            crypter.set(new Crypter(keyChain));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void syncWithConfig(List<SecretConfiguration> secretConfiguration) {
        reloadSecretsFromLocalStore();
        save(secretConfiguration);
    }

    /**
    Downloaded secrets are added to the local store based on the component configuration only.
    Cache should be updated whenever the store is updated.
     */
    private void save(List<SecretConfiguration> secretConfiguration) {
        try (LockScope ls = LockScope.lock(localStoreLock)) {
            List<AWSSecretResponse> responses = new ArrayList<>();
            if (!secrets.isEmpty()) {
                secretConfiguration.forEach((secretConfig) -> {
                    secretConfig.getLabels().forEach((label) -> {
                        String arn = secretConfig.getArn();
                        if (secrets.containsKey(arn) && secrets.get(arn).responseMap.containsKey(label)) {
                            responses.add(secrets.get(arn).responseMap.get(label));
                        }
                    });
                });
            }

            try {
                secretStore.saveAll(new SecretDocument(responses));
            } catch (SecretManagerException e) {
                logger.atError().log("Unable to update the local store.");
            }
        }
    }


    /**
     *  {
     * "secret1-arn" :{
     *  "AWSCURRENT":{"name": "secret1", "arn": "secret1-arn", "versionId": "secret1-v1", versionStages:["AWSCURRENT"]},
     *  "NEW" : {"name": "secret1", "arn": "secret1-arn", "versionId": "secret1-v2", versionStages:["NEW", "LATEST"]},
     *  "LATEST": {"name": "secret1", "arn": "secret1-arn", "versionId": "secret1-v2", versionStages:["NEW", "LATEST"]}
     *     }
     * "secret2-arn" :{
     *  "AWSCURRENT":{"name": "secret2", "arn": "secret2-arn", "versionId": "secret2-v1", versionStages:["AWSCURRENT"]}
     *  }
     * }
     * When a latest secret with "NEW" stage is downloaded from cloud, if "NEW" points to version "secret1-v3"
     * and "LATEST" still points to "secret1-v2".
     * Case 1: LATEST label secret is downloaded, downloading NEW failed.
     * "secret1-arn" :{
     *  "AWSCURRENT":{"name": "secret1", "arn": "secret1-arn", "versionId": "secret1-v1", versionStages:["AWSCURRENT"]},
     *  "LATEST": {"name": "secret1", "arn": "secret1-arn", "versionId": "secret1-v2", versionStages:["LATEST"]}
     *     }
     *     ..
     *  Case 2: NEW label secret is downloaded, downloading LATEST failed.
     * "secret1-arn" :{
     *  "AWSCURRENT":{"name": "secret1", "arn": "secret1-arn", "versionId": "secret1-v1", versionStages:["AWSCURRENT"]},
     *  "NEW" : {"name": "secret1", "arn": "secret1-arn", "versionId": "secret1-v2", versionStages:["NEW"]},
     *  "LATEST": {"name": "secret1", "arn": "secret1-arn", "versionId": "secret1-v2", versionStages:["LATEST"]}
     *     }
     *     ..
     * }
     * @param result secret response to encrypt
     * @param secretConfiguration secret manager component configuration
     * @throws SecretCryptoException when encryption fails
     */
    public void updateWithSecret(GetSecretValueResponse result, List<SecretConfiguration> secretConfiguration)
            throws SecretCryptoException {
        AWSSecretResponse secretResponse = encryptAWSResponse(result);
        updateWithSecret(secretResponse, secretConfiguration);
    }

    private void updateWithSecret(AWSSecretResponse secretResponse, List<SecretConfiguration> secretConfiguration) {
        try (LockScope ls = LockScope.lock(localStoreLock)) {
            reloadSecretsFromLocalStore();
            String arn = secretResponse.getArn();
            if (secrets.containsKey(arn)) {
                Labels secLabelMap = secrets.get(arn);
                secLabelMap.responseMap.entrySet()
                        .removeIf(entry -> entry.getValue().getVersionId().equals(secretResponse.getVersionId()));
                secLabelMap.responseMap.forEach((k, v) -> {
                    ArrayList<String> list = new ArrayList<>(v.getVersionStages());
                    list.removeAll(new ArrayList<>(secretResponse.getVersionStages()));
                    v.setVersionStages(list);
                });
            }
            secrets.putIfAbsent(arn, new Labels(new HashMap<>()));
            secretResponse.getVersionStages().forEach((label) -> {
                secrets.get(arn).responseMap.put(label, secretResponse);
            });
            this.save(secretConfiguration);
        }
    }

    private AWSSecretResponse encryptAWSResponse(GetSecretValueResponse result) throws SecretCryptoException {
        String encodedSecretString = null;
        if (result.secretString() != null) {
            byte[] encryptedSecretString =
                    getCrypter().encrypt(result.secretString().getBytes(StandardCharsets.UTF_8), result.arn());
            encodedSecretString = Base64.getEncoder().encodeToString(encryptedSecretString);
        }
        String encodedSecretBinary = null;
        if (result.secretBinary() != null) {
            byte[] encryptedSecretBinary = getCrypter().encrypt(result.secretBinary().asByteArray(), result.arn());
            encodedSecretBinary = Base64.getEncoder().encodeToString(encryptedSecretBinary);
        }
        // reuse all fields except the secret value, replace secret value with encrypted value
        return AWSSecretResponse.builder().encryptedSecretString(encodedSecretString)
                .encryptedSecretBinary(encodedSecretBinary).name(result.name()).arn(result.arn())
                .createdDate(result.createdDate().toEpochMilli()).versionId(result.versionId())
                .versionStages(result.versionStages()).build();
    }

    /**
     * Decrypt encrypted secret response to IPC GetSecretValueResponse object.
     * @param awsSecretResponse encrypted secret
     * @return IPC GetSecretValueResponse structure
     * @throws SecretCryptoException crypto exception
     */
    public GetSecretValueResponse decrypt(AWSSecretResponse awsSecretResponse) throws SecretCryptoException {
        String decryptedSecretString = null;
        if (awsSecretResponse.getEncryptedSecretString() != null) {
            byte[] decryptedSecret =
                    getCrypter().decrypt(Base64.getDecoder().decode(awsSecretResponse.getEncryptedSecretString()),
                            awsSecretResponse.getArn());
            decryptedSecretString = new String(decryptedSecret, StandardCharsets.UTF_8);
        }

        SdkBytes decryptedSecretBinary = null;
        if (awsSecretResponse.getEncryptedSecretBinary() != null) {
            byte[] decryptedSecret =
                    getCrypter().decrypt(Base64.getDecoder().decode(awsSecretResponse.getEncryptedSecretBinary()),
                            awsSecretResponse.getArn());
            decryptedSecretBinary = SdkBytes.fromByteArray(decryptedSecret);
        }

        return GetSecretValueResponse.builder().secretString(decryptedSecretString).secretBinary(decryptedSecretBinary)
                .name(awsSecretResponse.getName()).arn(awsSecretResponse.getArn())
                .createdDate(Instant.ofEpochMilli(awsSecretResponse.getCreatedDate()))
                .versionId(awsSecretResponse.getVersionId()).versionStages(awsSecretResponse.getVersionStages())
                .build();
    }

    /**
     * Store secrets map.
     * For the given secrets manager configuration
     * {
     * "cloudSecrets":[
     *     {"arn":"secret1-arn", "labels":["AWSCURRENT", "NEW"]},
     *     {"arn":"secret2-arn", "labels":["AWSCURRENT"]}
     *   ]
     * }
     * Local store (runtime config) contains secrets in the following format
     * [secrets:
     * {"name": "secret1", "arn": "secret1-arn", "versionId": "secret1-v1", versionStages:["AWSCURRENT"]},
     * {"name": "secret1", "arn": "secret1-arn", "versionId": "secret1-v2", versionStages:["NEW", "LATEST"]},
     * {"name": "secret2", "arn": "secret2-arn", "versionId": "secret2-v1", versionStages:["AWSCURRENT"]}
     * ]
     * The following method returns the following structure for the same secrets only when decrypting the secret is
     * successful
     * {
     * "secret1-arn" :{
     *  "AWSCURRENT":{"name": "secret1", "arn": "secret1-arn", "versionId": "secret1-v1", versionStages:["AWSCURRENT"]},
     *  "NEW" : {"name": "secret1", "arn": "secret1-arn", "versionId": "secret1-v2", versionStages:["NEW", "LATEST"]},
     *  "LATEST": {"name": "secret1", "arn": "secret1-arn", "versionId": "secret1-v2", versionStages:["NEW", "LATEST"]}
     * }
     * "secret2-arn" : {
     *   "AWSCURRENT":{"name": "secret2", "arn": "secret2-arn", "versionId": "secret2-v1", versionStages:["AWSCURRENT"]}
     *  }
     * }
     */
    private void reloadSecretsFromLocalStore() {
        try (LockScope ls = LockScope.lock(localStoreLock)) {
            SecretDocument doc;
            try {
                doc = secretStore.getAll();
            } catch (SecretManagerException e) {
                logger.atWarn().log("Cannot read secrets from the local store");
                return;
            }
            if (doc == null || doc.getSecrets() == null || doc.getSecrets().isEmpty()) {
                return;
            }
            for (AWSSecretResponse secretResponse : doc.getSecrets()) {
                try {
                    decrypt(secretResponse);
                } catch (SecretCryptoException e) {
                    logger.atWarn().kv("secretArn", secretResponse.getArn()).kv("label", secretResponse.getVersionId())
                            .log("Unable to decrypt the secret in local store.");
                    continue;
                }
                secrets.putIfAbsent(secretResponse.getArn(), new Labels(new HashMap<>()));
                secretResponse.getVersionStages().forEach((label) -> {
                    secrets.get(secretResponse.getArn()).responseMap.put(label, secretResponse);
                });
            }
        }
    }

    private static class Labels {
        HashMap<String, AWSSecretResponse> responseMap;

        public Labels(HashMap<String, AWSSecretResponse> responseMap) {
            this.responseMap = responseMap;
        }
    }
}
