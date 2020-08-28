package com.aws.iot.greengrass.secretmanager;

import com.aws.iot.evergreen.config.Topic;
import com.aws.iot.evergreen.util.Coerce;
import com.aws.iot.greengrass.secretmanager.exception.SecretManagerException;
import com.aws.iot.greengrass.secretmanager.kernel.KernelClient;
import com.aws.iot.greengrass.secretmanager.model.SecretDocument;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import javax.inject.Inject;

import static com.aws.iot.evergreen.kernel.EvergreenService.SERVICES_NAMESPACE_TOPIC;
import static com.aws.iot.greengrass.secretmanager.SecretManagerService.SECRET_MANAGER_SERVICE_NAME;

/**
 * File based DAO for secrets. This class persists {@link SecretDocument} to a pre defined
 * directory. Both getAll and saveAll are protected by {@link synchronized}, which guarantees
 * only a single thread can either read or write the store at any point of time. The class
 * is also immutable with all fields being final.
 */
public class FileSecretDao implements SecretDao<SecretDocument> {
    public static final String SECRET_RESPONSE_TOPIC = "secretResponse";
    private final KernelClient kernelClient;
    private static final ObjectMapper OBJECT_MAPPER =
            new ObjectMapper().configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);

    /**
     * Constructor.
     * @param kernelClient kernel client for accessing kernel root dir
     * @throws SecretManagerException if root dir does not exist
     */
    @Inject
    public FileSecretDao(KernelClient kernelClient) throws SecretManagerException {
        this.kernelClient = kernelClient;
    }

    /**
     * Retrieve secret document from underlying file store.
     * @return {@link SecretDocument} containing all persisted secrets
     * @throws SecretManagerException when there is any issue reading the store.
     */
    public synchronized SecretDocument getAll() throws SecretManagerException {
        Topic secretResponseTopic = kernelClient.getConfig().lookup(SERVICES_NAMESPACE_TOPIC,
                    SECRET_MANAGER_SERVICE_NAME, SECRET_RESPONSE_TOPIC);
        if (secretResponseTopic.getOnce() == null) {
            throw new SecretManagerException("No secrets found in file");
        }
        try {
            return OBJECT_MAPPER.readValue(Coerce.toString(secretResponseTopic), SecretDocument.class);
        } catch (IOException e) {
            throw new SecretManagerException("Cannot read secret response from store", e);
        }
    }

    /**
     * Save a secret document to underlying file store.
     * @param doc {@link SecretDocument} containing list of secrets to persist
     * @throws SecretManagerException when there is any issue writing to the store.
     */
    public synchronized void saveAll(SecretDocument doc) throws SecretManagerException {
        Topic secretTopic = kernelClient.getConfig().lookup(SERVICES_NAMESPACE_TOPIC,
                SECRET_MANAGER_SERVICE_NAME, SECRET_RESPONSE_TOPIC);
        try {
            secretTopic.withValue(OBJECT_MAPPER.writeValueAsString(doc));
        } catch (IOException e) {
            throw new SecretManagerException("Cannot write secret response to store", e);
        }
    }
}

