/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.store;

import com.aws.greengrass.config.Topic;
import com.aws.greengrass.secretmanager.SecretManagerService;
import com.aws.greengrass.secretmanager.exception.NoSecretFoundException;
import com.aws.greengrass.secretmanager.exception.SecretManagerException;
import com.aws.greengrass.secretmanager.kernel.KernelClient;
import com.aws.greengrass.secretmanager.model.AWSSecretResponse;
import com.aws.greengrass.secretmanager.model.SecretDocument;
import com.aws.greengrass.util.Coerce;
import com.aws.greengrass.util.Utils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import javax.inject.Inject;

import static com.aws.greengrass.lifecyclemanager.GreengrassService.RUNTIME_STORE_NAMESPACE_TOPIC;
import static com.aws.greengrass.lifecyclemanager.GreengrassService.SERVICES_NAMESPACE_TOPIC;

/**
 * File based DAO for secrets. This class persists {@link SecretDocument} to a pre defined
 * directory. Both getAll and saveAll are protected by {@link synchronized}, which guarantees
 * only a single thread can either read or write the store at any point of time. The class
 * is also immutable with all fields being final.
 */
public class FileSecretStore implements SecretStore<SecretDocument, AWSSecretResponse> {
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
    public FileSecretStore(KernelClient kernelClient) throws SecretManagerException {
        this.kernelClient = kernelClient;
    }

    /**
     * Retrieve secret document from underlying file store.
     * @return {@link SecretDocument} containing all persisted secrets
     * @throws SecretManagerException when there is any issue reading the store.
     */
    public SecretDocument getAll() throws SecretManagerException {
        Topic secretResponseTopic = kernelClient.getConfig().lookup(SERVICES_NAMESPACE_TOPIC,
                    SecretManagerService.SECRET_MANAGER_SERVICE_NAME, RUNTIME_STORE_NAMESPACE_TOPIC,
                SECRET_RESPONSE_TOPIC);
        if (secretResponseTopic.getOnce() == null) {
            throw new NoSecretFoundException("No secrets found in file");
        }
        try {
            return OBJECT_MAPPER.readValue(Coerce.toString(secretResponseTopic), SecretDocument.class);
        } catch (IOException e) {
            throw new SecretManagerException("Cannot read secret response from store", e);
        }
    }

    /**
     * Retrieve a certain secret from underlying file store.
     * @param secretArn arn of the secret
     * @param label label of the secret
     * @return {@link AWSSecretResponse} the secret given the arn and label, null if not present
     * @throws SecretManagerException when there is any issue reading the store.
     */
    public AWSSecretResponse get(String secretArn, String label) throws SecretManagerException {
        if (Utils.isEmpty(secretArn) || Utils.isEmpty(label)) {
            throw new SecretManagerException("Cannot get secret response from store given empty arn or label");
        }
        try {
            SecretDocument secrets = getAll();
            for (AWSSecretResponse secretResponse : secrets.getSecrets()) {
                if (secretArn.equals(secretResponse.getArn()) && secretResponse.getVersionStages().contains(label)) {
                    return secretResponse;
                }
            }
            return null;
        } catch (NoSecretFoundException e) {
            return null;
        }
    }

    @Override
    public void save(AWSSecretResponse encryptedResult) throws SecretManagerException, JsonProcessingException {
        Topic secretTopic = kernelClient.getConfig()
                .lookup(SERVICES_NAMESPACE_TOPIC, SecretManagerService.SECRET_MANAGER_SERVICE_NAME,
                        RUNTIME_STORE_NAMESPACE_TOPIC, SECRET_RESPONSE_TOPIC);
        SecretDocument doc = OBJECT_MAPPER.readValue(secretTopic.toPOJO().toString(), SecretDocument.class);
        List<AWSSecretResponse> responseList = doc.getSecrets();
        // If the existing secrets in the store contain the version stages(labels) of the newly added secret, we have
        // to remove those labels as labels are unique across different versions of a secret.
        Iterator<AWSSecretResponse> secretsItr =
                responseList.stream().filter(secret -> secret.getArn().equals(encryptedResult.getArn())).iterator();
        encryptedResult.getVersionStages().forEach((label -> {
            while (secretsItr.hasNext()) {
                AWSSecretResponse response = secretsItr.next();
                response.getVersionStages().remove(label);
            }
        }));
        responseList.add(encryptedResult);
        SecretDocument updatedDoc = SecretDocument.builder().secrets(responseList).build();
        try {
            secretTopic.withValue(OBJECT_MAPPER.writeValueAsString(updatedDoc));
        } catch (JsonProcessingException e) {
            throw new SecretManagerException("Cannot write secret response to store", e);
        }
    }

    /**
     * Save a secret document to underlying file store.
     *
     * @param doc {@link SecretDocument} containing list of secrets to persist
     * @throws SecretManagerException when there is any issue writing to the store.
     */
    public void saveAll(SecretDocument doc) throws SecretManagerException {
        Topic secretTopic = kernelClient.getConfig().lookup(SERVICES_NAMESPACE_TOPIC,
                SecretManagerService.SECRET_MANAGER_SERVICE_NAME, RUNTIME_STORE_NAMESPACE_TOPIC,
                SECRET_RESPONSE_TOPIC);
        try {
            secretTopic.withValue(OBJECT_MAPPER.writeValueAsString(doc));
        } catch (IOException e) {
            throw new SecretManagerException("Cannot write secret response to store", e);
        }
    }
}

