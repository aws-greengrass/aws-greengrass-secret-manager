/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager;

import com.aws.greengrass.config.Configuration;
import com.aws.greengrass.config.Topic;
import com.aws.greengrass.secretmanager.exception.SecretManagerException;
import com.aws.greengrass.secretmanager.kernel.KernelClient;
import com.aws.greengrass.secretmanager.model.AWSSecretResponse;
import com.aws.greengrass.secretmanager.model.SecretDocument;
import com.aws.greengrass.secretmanager.store.FileSecretStore;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import com.aws.greengrass.util.Coerce;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static com.aws.greengrass.lifecyclemanager.GreengrassService.RUNTIME_STORE_NAMESPACE_TOPIC;
import static com.aws.greengrass.lifecyclemanager.GreengrassService.SERVICES_NAMESPACE_TOPIC;
import static com.aws.greengrass.secretmanager.store.FileSecretStore.SECRET_RESPONSE_TOPIC;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith({MockitoExtension.class, GGExtension.class})
class FileSecretStoreTest {
    private final static String SECRET_NAME_1 = "secretA";
    private final static String SECRET_STRING_1 = "Its a secret!!";
    private final static String ARN_1 = "arn:aws:secretsmanager:us-east-1:9988977227:secret:snow-H9ySfh";
    private final static String VERSION_ID_1 = UUID.randomUUID().toString();
    private final static String LABEL1 = "new label1";
    private final static String LABEL2 = "new label2";
    private final static long DATE_1 = Instant.now().toEpochMilli();
    private final static String SECRET_NAME_2 = "secretB";
    private final static String SECRET_STRING_2 = "Its a secret!!, but another one";
    private final static String ARN_2 = "arn:aws:secretsmanager:us-east-1:9988977227:secret:newtake-H9ySfh";
    private final static String VERSION_ID_2 = UUID.randomUUID().toString();
    private final static String LABEL3 = "new label3";
    private final static String LABEL4 = "new label4";
    private final static long DATE_2 = Instant.now().minusSeconds(100L).toEpochMilli();

    @Mock
    KernelClient mockKernelClient;

    @Mock
    Configuration mockConfiguration;

    @Captor
    ArgumentCaptor<String> stringCapor;

    private List<AWSSecretResponse> getSecrets() {
        List<AWSSecretResponse> secrets = new ArrayList<>();
        AWSSecretResponse secret1 = AWSSecretResponse.builder()
                .name(SECRET_NAME_1)
                .arn(ARN_1)
                .createdDate(DATE_1)
                .versionId(VERSION_ID_1)
                .encryptedSecretString(SECRET_STRING_1)
                .versionStages(Arrays.asList(new String[]{LABEL1, LABEL2}))
                .build();

        AWSSecretResponse secret2 = AWSSecretResponse.builder()
                .name(SECRET_NAME_2)
                .arn(ARN_2)
                .createdDate(DATE_2)
                .versionId(VERSION_ID_2)
                .encryptedSecretString(SECRET_STRING_2)
                .versionStages(Arrays.asList(new String[]{LABEL3, LABEL4}))
                .build();

        secrets.add(secret1);
        secrets.add(secret2);
        return secrets;
    }

    @BeforeEach
    void setup() throws IOException {
        when(mockKernelClient.getConfig()).thenReturn(mockConfiguration);
    }

    @Test
    void GIVEN_dao_store_WHEN_secrets_saved_THEN_get_returns_them() throws SecretManagerException, IOException {
        FileSecretStore dao = new FileSecretStore(mockKernelClient);
        Topic mockTopic = mock(Topic.class);
        when(mockConfiguration.lookup(SERVICES_NAMESPACE_TOPIC,
                SecretManagerService.SECRET_MANAGER_SERVICE_NAME, RUNTIME_STORE_NAMESPACE_TOPIC,
                SECRET_RESPONSE_TOPIC)).thenReturn(mockTopic);


        List<AWSSecretResponse> response = getSecrets();
        SecretDocument doc = new SecretDocument(response);
        dao.saveAll(doc);

        verify(mockTopic, times(1)).withValue(stringCapor.capture());

        ObjectMapper mapper =
                new ObjectMapper().configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);

        SecretDocument writtendoc = mapper.readValue(stringCapor.getValue(), SecretDocument.class);
        AWSSecretResponse writtenSecret1 = writtendoc.getSecrets().get(0);
        assertEquals(SECRET_NAME_1, writtenSecret1.getName());
        assertEquals(SECRET_STRING_1, writtenSecret1.getEncryptedSecretString());
        assertEquals(ARN_1, writtenSecret1.getArn());
        assertEquals(VERSION_ID_1, writtenSecret1.getVersionId());
        assertEquals(DATE_1, writtenSecret1.getCreatedDate());
        assertThat(writtenSecret1.getVersionStages(), hasItem(LABEL1));
        assertThat(writtenSecret1.getVersionStages(), hasItem(LABEL2));

        AWSSecretResponse writtenSecret2 = writtendoc.getSecrets().get(1);
        assertEquals(SECRET_NAME_2, writtenSecret2.getName());
        assertEquals(SECRET_STRING_2, writtenSecret2.getEncryptedSecretString());
        assertEquals(ARN_2, writtenSecret2.getArn());
        assertEquals(VERSION_ID_2, writtenSecret2.getVersionId());
        assertEquals(DATE_2, writtenSecret2.getCreatedDate());
        assertThat(writtenSecret2.getVersionStages(), hasItem(LABEL3));
        assertThat(writtenSecret2.getVersionStages(), hasItem(LABEL4));


        // Validate that read works now
        when(mockTopic.getOnce()).thenReturn(stringCapor.getValue());
        // Now read the structure from the dao object
        AWSSecretResponse firstSecretFromDao = dao.getAll().getSecrets().get(0);

        assertEquals(SECRET_NAME_1, firstSecretFromDao.getName());
        assertEquals(SECRET_STRING_1, firstSecretFromDao.getEncryptedSecretString());
        assertEquals(ARN_1, firstSecretFromDao.getArn());
        assertEquals(VERSION_ID_1, firstSecretFromDao.getVersionId());
        assertEquals(DATE_1, firstSecretFromDao.getCreatedDate());
        assertThat(firstSecretFromDao.getVersionStages(), hasItem(LABEL1));
        assertThat(firstSecretFromDao.getVersionStages(), hasItem(LABEL2));

        AWSSecretResponse secondSecretFromDao = dao.getAll().getSecrets().get(1);
        assertEquals(SECRET_NAME_2, secondSecretFromDao.getName());
        assertEquals(SECRET_STRING_2, secondSecretFromDao.getEncryptedSecretString());
        assertEquals(ARN_2, secondSecretFromDao.getArn());
        assertEquals(VERSION_ID_2, secondSecretFromDao.getVersionId());
        assertEquals(DATE_2, secondSecretFromDao.getCreatedDate());
        assertThat(secondSecretFromDao.getVersionStages(), hasItem(LABEL3));
        assertThat(secondSecretFromDao.getVersionStages(), hasItem(LABEL4));

        // Validate get with arn and label
        AWSSecretResponse secretFromDaoArn1Label1 = dao.get(ARN_1, LABEL1);
        AWSSecretResponse secretFromDaoArn1Label2 = dao.get(ARN_1, LABEL2);
        assertEquals(secretFromDaoArn1Label1,secretFromDaoArn1Label2);
        assertEquals(SECRET_NAME_1, secretFromDaoArn1Label1.getName());
        assertEquals(SECRET_STRING_1, secretFromDaoArn1Label1.getEncryptedSecretString());
        assertEquals(ARN_1, secretFromDaoArn1Label1.getArn());
        assertEquals(VERSION_ID_1, secretFromDaoArn1Label1.getVersionId());
        assertEquals(DATE_1, secretFromDaoArn1Label1.getCreatedDate());
        assertThat(secretFromDaoArn1Label1.getVersionStages(), hasItem(LABEL1));
        assertThat(secretFromDaoArn1Label1.getVersionStages(), hasItem(LABEL2));

        AWSSecretResponse secretFromDaoArn2Label3 = dao.get(ARN_2, LABEL3);
        AWSSecretResponse secretFromDaoArn2Label4 = dao.get(ARN_2, LABEL4);
        assertEquals(secretFromDaoArn2Label3,secretFromDaoArn2Label4);
        assertEquals(SECRET_NAME_2, secretFromDaoArn2Label3.getName());
        assertEquals(SECRET_STRING_2, secretFromDaoArn2Label3.getEncryptedSecretString());
        assertEquals(ARN_2, secretFromDaoArn2Label3.getArn());
        assertEquals(VERSION_ID_2, secretFromDaoArn2Label3.getVersionId());
        assertEquals(DATE_2, secretFromDaoArn2Label3.getCreatedDate());
        assertThat(secretFromDaoArn2Label3.getVersionStages(), hasItem(LABEL3));
        assertThat(secretFromDaoArn2Label3.getVersionStages(), hasItem(LABEL4));

        assertNull(dao.get("invalidArn", LABEL1));
        assertNull(dao.get(ARN_1, "invalidLabel"));

        assertThrows(SecretManagerException.class, () ->dao.get("", LABEL1));
        assertThrows(SecretManagerException.class, () ->dao.get(ARN_1, ""));
        assertThrows(SecretManagerException.class, () ->dao.get(null, LABEL1));
        assertThrows(SecretManagerException.class, () ->dao.get(ARN_1, null));
    }

    @Test
    void GIVEN_dao_store_WHEN_objectmapper_error_THEN_throws() throws SecretManagerException {
        FileSecretStore dao = new FileSecretStore(mockKernelClient);
        Topic mockTopic = mock(Topic.class);
        when(mockConfiguration.lookup(SERVICES_NAMESPACE_TOPIC, SecretManagerService.SECRET_MANAGER_SERVICE_NAME,
                RUNTIME_STORE_NAMESPACE_TOPIC, SECRET_RESPONSE_TOPIC)).thenReturn(mockTopic);
        // Make readValue() throw JsonProcessingException
        when(Coerce.toString(mockTopic)).thenReturn(mockTopic.getClass().getName());
        assertThrows(SecretManagerException.class, () -> dao.getAll());

        List<AWSSecretResponse> response = getSecrets();
        SecretDocument doc = new SecretDocument(response);
        // Make withValue() throw IOException
        when(mockTopic.withValue(anyString())).thenAnswer(invocation -> {
            throw new IOException();
        });
        assertThrows(SecretManagerException.class, () -> dao.saveAll(doc));
    }
}
