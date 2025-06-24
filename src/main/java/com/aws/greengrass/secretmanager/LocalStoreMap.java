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
import com.aws.greengrass.security.exceptions.KeyLoadingException;
import com.aws.greengrass.security.exceptions.ServiceUnavailableException;
import com.aws.greengrass.util.Coerce;
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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import javax.inject.Inject;

import static com.aws.greengrass.deployment.DeviceConfiguration.DEVICE_PARAM_CERTIFICATE_FILE_PATH;
import static com.aws.greengrass.deployment.DeviceConfiguration.DEVICE_PARAM_PRIVATE_KEY_PATH;

public class LocalStoreMap {
    private final Logger logger = LogManager.getLogger(LocalStoreMap.class);
    private final Map<String, Labels> secrets;
    private final SecretStore<SecretDocument, AWSSecretResponse> secretStore;
    private final AtomicReference<Crypter> crypter = new AtomicReference<>();
    private final SecurityService securityService;
    private final Object crypterLockObject = new Object();
    private final Object localStoreLockObject = new Object();

    @Inject
    LocalStoreMap(SecurityService securityService, FileSecretStore dao, DeviceConfiguration deviceConfiguration) {
        this.secretStore = dao;
        this.securityService = securityService;
        deviceConfiguration.onAnyChange(((whatHappened, node) -> {
            if (validUpdate(node, DEVICE_PARAM_CERTIFICATE_FILE_PATH) || validUpdate(node,
                    DEVICE_PARAM_PRIVATE_KEY_PATH)) {
                // TODO: Trigger downloading new secrets from cloud and encrypt them with the new creds.
                synchronized (crypterLockObject) {
                    crypter.set(null);
                }
            }
        }));
        this.secrets = new HashMap<>();
    }

    private boolean validUpdate(Node node, String key) {
        return node != null && node.childOf(key) && Utils.isNotEmpty(Coerce.toString(node));
    }

    protected Crypter getCrypter() throws SecretCryptoException {
        synchronized (crypterLockObject) {
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

    private void loadCrypter() throws KeyLoadingException, ServiceUnavailableException, SecretCryptoException {
        URI privateKeyUri = securityService.getDeviceIdentityPrivateKeyURI();
        URI certUri = securityService.getDeviceIdentityCertificateURI();
        KeyPair kp = securityService.getKeyPair(privateKeyUri, certUri);
        MasterKey masterKey = RSAMasterKey.createInstance(kp.getPublic(), kp.getPrivate());
        KeyChain keyChain = new KeyChain();
        keyChain.addMasterKey(masterKey);
        crypter.set(new Crypter(keyChain));
    }

    public void syncWithConfig(List<SecretConfiguration> secretConfiguration) {
        reloadSecretsFromLocalStore();
        save(secretConfiguration);
    }

    /**
    Downloaded secrets are added to the local store based on the component configuration only.
    Cache should be updated whenever the store is updated.
     */
    private boolean save(List<SecretConfiguration> secretConfiguration) {
        synchronized (localStoreLockObject) {
            List<AWSSecretResponse> responses = new ArrayList<>();
            if (!secrets.isEmpty()) {
                secretConfiguration.forEach((secretConfig) -> {
                    secretConfig.getLabels().forEach((label) -> {
                        String arn = secretConfig.getArn();
                        secrets.entrySet().stream().filter(entry -> entry.getKey().contains(arn))
                                .filter(entry -> entry.getValue().responseMap.containsKey(label))
                                .forEach(entry -> responses.add(entry.getValue().responseMap.get(label)));
                    });
                });
            }

            try {
                HashSet<AWSSecretResponse> latestSecrets = new HashSet<>(responses);
                HashSet<AWSSecretResponse> existingSecrets = new HashSet<>(secretStore.getAll().getSecrets());
                if (latestSecrets.equals(existingSecrets)) {
                    logger.atDebug().log("Not updating local store as the secrets are not modified");
                    return false;
                }
                secretStore.saveAll(new SecretDocument(responses));
                return true;
            } catch (SecretManagerException e) {
                logger.atError().log("Unable to update the local store.");
            }
            return false;
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
     * @return true if the secret is updated in the local store, false otherwise.
     * @throws SecretCryptoException when encryption fails
     */
    public boolean updateWithSecret(GetSecretValueResponse result, List<SecretConfiguration> secretConfiguration) {
        Labels labels = secrets.get(result.arn());
        boolean isSecretInStore = labels != null && labels.responseMap != null;
        // If the downloaded secret doesn't exist in the store, then update the store with that secret
        // If a secret exists in the store but is different from the downloaded secret, then update the store
        HashSet<String> downloadedLabels = new HashSet<>(result.versionStages());
        HashSet<String> existingLabels = isSecretInStore ? new HashSet<>(labels.responseMap.keySet()) : new HashSet<>();
        boolean shouldUpdateSecretInStore =
                !isSecretInStore || !downloadedLabels.equals(existingLabels) || downloadedLabels.stream()
                        .anyMatch((label) -> {
                            AWSSecretResponse response = labels.responseMap.get(label);
                            // For each label of the downloaded secret, compare it secret version with the secret
                            // version of the existing labels in the local store.
                            return response == null || !response.getVersionId().equals(result.versionId());
                        });
        if (shouldUpdateSecretInStore) {
            try {
                AWSSecretResponse secretResponse = encryptAWSResponse(result);
                return updateWithSecret(secretResponse, secretConfiguration);
            } catch (SecretCryptoException e) {
                logger.atWarn().setCause(e).log("Unable to encrypt secret, skip saving to disk");
            }
        }
        return false;
    }

    private boolean updateWithSecret(AWSSecretResponse secretResponse, List<SecretConfiguration> secretConfiguration) {
        synchronized (localStoreLockObject) {
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
            return this.save(secretConfiguration);
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
        synchronized (localStoreLockObject) {
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
