/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager;

import com.aws.greengrass.config.Configuration;
import com.aws.greengrass.config.Topic;
import com.aws.greengrass.config.UnsupportedInputTypeException;
import com.aws.greengrass.dependency.Context;
import com.aws.greengrass.deployment.DeviceConfiguration;
import com.aws.greengrass.secretmanager.crypto.Crypter;
import com.aws.greengrass.secretmanager.crypto.KeyChain;
import com.aws.greengrass.secretmanager.crypto.MasterKey;
import com.aws.greengrass.secretmanager.crypto.RSAMasterKey;
import com.aws.greengrass.secretmanager.exception.SecretCryptoException;
import com.aws.greengrass.secretmanager.exception.SecretManagerException;
import com.aws.greengrass.secretmanager.exception.v1.GetSecretException;
import com.aws.greengrass.secretmanager.kernel.KernelClient;
import com.aws.greengrass.secretmanager.model.AWSSecretResponse;
import com.aws.greengrass.secretmanager.model.SecretConfiguration;
import com.aws.greengrass.secretmanager.model.SecretDocument;
import com.aws.greengrass.secretmanager.store.FileSecretStore;
import com.aws.greengrass.security.SecurityService;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import com.aws.greengrass.util.EncryptionUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.sql.Date;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static com.aws.greengrass.componentmanager.KernelConfigResolver.CONFIGURATION_CONFIG_KEY;
import static com.aws.greengrass.secretmanager.SecretManagerService.SECRETS_TOPIC;
import static com.aws.greengrass.testcommons.testutilities.ExceptionLogProtector.ignoreExceptionOfType;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith({MockitoExtension.class, GGExtension.class})
class SecretManagerTest {
    private static final String LATEST_LABEL = "AWSCURRENT";
    private static final String SECRET_NAME_1 = "Secret1";
    private static final String SECRET_NAME_2 = "Secret2";
    private static final String SECRET_NAME_3 = "Secret3";

    private static final String SECRET_VALUE_1 = "password";
    private static final String SECRET_VALUE_2 = "newPassword";
    private static final String SECRET_VALUE_3 = "otherPassword";
    private static final byte[] SECRET_VALUE_BINARY_1 = SECRET_VALUE_1.getBytes();
    private static final byte[] SECRET_VALUE_BINARY_2 = SECRET_VALUE_2.getBytes();
    private static final byte[] SECRET_VALUE_BINARY_3 = SECRET_VALUE_3.getBytes();
    private static final String SECRET_VERSION_1 = UUID.randomUUID().toString();
    private static final String SECRET_VERSION_2 = UUID.randomUUID().toString();
    private static final String SECRET_VERSION_3 = UUID.randomUUID().toString();
    private static final String SECRET_LABEL_1 = "Label1";
    private static final String SECRET_LABEL_2 = "Label2";
    private static final String SECRET_LABEL_3 = "Label3";

    private static final Instant SECRET_DATE_1 = Instant.now();
    private static final Instant SECRET_DATE_2 = Instant.now();

    private static final String ARN_1 = "arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh";
    private static final String ARN_2 = "arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret2-32lYsd";
    private static final String ARN_3 = "arn:aws-us-gov:secretsmanager:us-east-1:999936977227:secret:Secret2-32lYsd";
    private static final String PARTIAL_ARN = "arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1";

    private String ENCRYPTED_SECRET_1;
    private String ENCRYPTED_SECRET_2;
    private String ENCRYPTED_SECRET_3;
    private String ENCRYPTED_SECRET_BINARY_1;
    private String ENCRYPTED_SECRET_BINARY_2;
    private String ENCRYPTED_SECRET_BINARY_3;
    private Crypter crypter;

    @Mock
    private AWSSecretClient mockAWSSecretClient;

    @Mock
    private FileSecretStore mockDao;

    @Mock
    private DeviceConfiguration mockDeviceConfiguration;

    private LocalStoreMap localStoreMap;

    @Mock
    private KernelClient mockKernelClient;

    private final SecurityService mockSecurityService = spy(new SecurityService(mockDeviceConfiguration));

    private final ExecutorService executorService = Executors.newSingleThreadExecutor();

    @Captor
    ArgumentCaptor<SecretDocument> documentArgumentCaptor;

    @Captor
    ArgumentCaptor<software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest> awsClientRequestCaptor;

    private void loadMockSecrets() throws JsonProcessingException, UnsupportedInputTypeException {
        SecretConfiguration secret1 = SecretConfiguration.builder().arn(ARN_1).build();
        SecretConfiguration secret2 = SecretConfiguration.builder().arn(ARN_2)
                .labels(Arrays.asList(LATEST_LABEL, SECRET_LABEL_1)).build();
        SecretConfiguration secret3 = SecretConfiguration.builder().arn(ARN_3).build();
        ArrayList<SecretConfiguration> config_ = new ArrayList<SecretConfiguration>() {{
            add(secret1);
            add(secret2);
            add(secret3);
        }};
        Configuration config = new Configuration(new Context());
        config.lookupTopics("services", SecretManagerService.SECRET_MANAGER_SERVICE_NAME)
                .lookup(CONFIGURATION_CONFIG_KEY, SECRETS_TOPIC).withValueChecked(config_);
        doReturn(config).when(mockKernelClient).getConfig();
    }

    private void getMockSecretsWithPartialArn() throws UnsupportedInputTypeException {
        SecretConfiguration secret = SecretConfiguration.builder().arn(PARTIAL_ARN).build();
        Configuration config = new Configuration(new Context());
        config.lookupTopics("services", SecretManagerService.SECRET_MANAGER_SERVICE_NAME)
                .lookup(CONFIGURATION_CONFIG_KEY, SECRETS_TOPIC).withValueChecked(new ArrayList<SecretConfiguration>() {{
                    add(secret);
                }});
        doReturn(config).when(mockKernelClient).getConfig();
    }

    @AfterEach
    void teardown() {
        executorService.shutdownNow();
    }

    @BeforeEach
    void setup() throws Exception {
        lenient().doReturn(getClass().getResource("privateKey.pem").toURI()).when(mockSecurityService)
                .getDeviceIdentityPrivateKeyURI();
        lenient().doReturn(getClass().getResource("cert.pem").toURI()).when(mockSecurityService)
                .getDeviceIdentityCertificateURI();
        Configuration mockConfiguration = mock(Configuration.class);
        lenient().when(mockKernelClient.getConfig()).thenReturn(mockConfiguration);
        Topic mockTopic = mock(Topic.class);
        lenient().when(mockConfiguration.lookup(anyString(), anyString(), anyString())).thenReturn(mockTopic);
        KeyPair kp = EncryptionUtils.loadPrivateKeyPair(Paths.get(getClass().getResource("privateKey.pem").toURI()));

        MasterKey masterKey = RSAMasterKey.createInstance(kp.getPublic(), kp.getPrivate());
        KeyChain keyChain = new KeyChain();
        keyChain.addMasterKey(masterKey);
        this.crypter = new Crypter(keyChain);
        ENCRYPTED_SECRET_1 = Base64.getEncoder()
                .encodeToString(crypter.encrypt(SECRET_VALUE_1.getBytes(StandardCharsets.UTF_8), ARN_1));
        ENCRYPTED_SECRET_2 = Base64.getEncoder()
                .encodeToString(crypter.encrypt(SECRET_VALUE_2.getBytes(StandardCharsets.UTF_8), ARN_2));
        ENCRYPTED_SECRET_3 = Base64.getEncoder()
                .encodeToString(crypter.encrypt(SECRET_VALUE_3.getBytes(StandardCharsets.UTF_8), ARN_3));
        ENCRYPTED_SECRET_BINARY_1 = Base64.getEncoder().encodeToString(crypter.encrypt(SECRET_VALUE_BINARY_1, ARN_1));
        ENCRYPTED_SECRET_BINARY_2 = Base64.getEncoder().encodeToString(crypter.encrypt(SECRET_VALUE_BINARY_2, ARN_2));
        ENCRYPTED_SECRET_BINARY_3 = Base64.getEncoder().encodeToString(crypter.encrypt(SECRET_VALUE_BINARY_3, ARN_3));
        localStoreMap = new LocalStoreMap(mockSecurityService, mockDao, mockDeviceConfiguration);
    }

    private GetSecretValueResponse getMockSecret(String name, String arn, Instant date, String secretString,
                                                 byte[] secretBinary, String versionId, List<String> versionStages) {
        if (secretBinary != null) {
            return GetSecretValueResponse.builder().name(name).arn(arn).createdDate(date).secretString(secretString)
                    .secretBinary(SdkBytes.fromByteArray(secretBinary)).versionId(versionId)
                    .versionStages(versionStages).build();
        } else {
            return GetSecretValueResponse.builder().name(name).arn(arn).createdDate(date).secretString(secretString)
                    .secretBinary(null).versionId(versionId).versionStages(versionStages).build();
        }
    }

    private GetSecretValueResponse getMockSecretA() {
        return getMockSecret(SECRET_NAME_1, ARN_1, SECRET_DATE_1, SECRET_VALUE_1, SECRET_VALUE_BINARY_1,
                SECRET_VERSION_1, Arrays.asList(LATEST_LABEL, SECRET_LABEL_1));
    }

    private GetSecretValueResponse getMockSecretAWithSecretString() {
        return getMockSecret(SECRET_NAME_1, ARN_1, SECRET_DATE_1, SECRET_VALUE_1, null, SECRET_VERSION_1,
                Arrays.asList(LATEST_LABEL, SECRET_LABEL_1));
    }

    private GetSecretValueResponse getMockSecretB() {
        return getMockSecret(SECRET_NAME_2, ARN_2, SECRET_DATE_2, SECRET_VALUE_2, SECRET_VALUE_BINARY_2,
                SECRET_VERSION_2, Arrays.asList(LATEST_LABEL, SECRET_LABEL_2));
    }

    private GetSecretValueResponse getMockSecretBWithSecretBinary() {
        return getMockSecret(SECRET_NAME_2, ARN_2, SECRET_DATE_2, null, SECRET_VALUE_BINARY_2, SECRET_VERSION_2,
                Arrays.asList(LATEST_LABEL, SECRET_LABEL_2));
    }

    private GetSecretValueResponse getMockSecretCWithSecretBinary() {
        return getMockSecret(SECRET_NAME_3, ARN_3, SECRET_DATE_2, null, SECRET_VALUE_BINARY_3, SECRET_VERSION_3,
                Arrays.asList(LATEST_LABEL, SECRET_LABEL_2));
    }

    private AWSSecretResponse loadMockDaoSecretA() {
        return AWSSecretResponse.builder().name(SECRET_NAME_1).arn(ARN_1).createdDate(SECRET_DATE_1.toEpochMilli())
                .encryptedSecretString(ENCRYPTED_SECRET_1).encryptedSecretBinary(ENCRYPTED_SECRET_BINARY_1)
                .versionStages(Arrays.asList(LATEST_LABEL, SECRET_LABEL_1)).versionId(SECRET_VERSION_1)
                .build();
    }

    private AWSSecretResponse loadMockDaoSecretB() {
        return AWSSecretResponse.builder().name(SECRET_NAME_2).arn(ARN_2).createdDate(SECRET_DATE_2.toEpochMilli())
                .encryptedSecretString(ENCRYPTED_SECRET_2).encryptedSecretBinary(ENCRYPTED_SECRET_BINARY_2)
                .versionStages(Arrays.asList(LATEST_LABEL, SECRET_LABEL_2)).versionId(SECRET_VERSION_2)
                .build();
    }

    private AWSSecretResponse loadMockDaoSecretAWithSecretString() {
        return AWSSecretResponse.builder().name(SECRET_NAME_1).arn(ARN_1).createdDate(SECRET_DATE_1.toEpochMilli())
                .encryptedSecretString(ENCRYPTED_SECRET_1)
                .versionStages(Arrays.asList(LATEST_LABEL, SECRET_LABEL_1)).versionId(SECRET_VERSION_1)
                .build();
    }

    private AWSSecretResponse loadMockDaoSecretBWithSecretBinary() {
        return AWSSecretResponse.builder().name(SECRET_NAME_2).arn(ARN_2).createdDate(SECRET_DATE_2.toEpochMilli())
                .encryptedSecretBinary(ENCRYPTED_SECRET_BINARY_2)
                .versionStages(Arrays.asList(LATEST_LABEL, SECRET_LABEL_2)).versionId(SECRET_VERSION_2)
                .build();
    }

    private AWSSecretResponse loadMockDaoSecretCWithSecretBinary() {
        return AWSSecretResponse.builder().name(SECRET_NAME_3).arn(ARN_3).createdDate(SECRET_DATE_2.toEpochMilli())
                .encryptedSecretBinary(ENCRYPTED_SECRET_BINARY_3)
                .versionStages(Arrays.asList(LATEST_LABEL, SECRET_LABEL_3)).versionId(SECRET_VERSION_3)
                .build();
    }

    @Test
    void GIVEN_cloud_secret_WHEN_binary_secret_set_THEN_only_binary_returned() throws Exception {
        loadMockSecrets();
        when(mockAWSSecretClient.getSecret(any()))
                .thenReturn(getMockSecretAWithSecretString())
                .thenReturn(getMockSecretBWithSecretBinary())
                .thenReturn(getMockSecretCWithSecretBinary());
        List<AWSSecretResponse> storedSecrets = new ArrayList<>();
        storedSecrets.add(loadMockDaoSecretAWithSecretString());
        storedSecrets.add(loadMockDaoSecretBWithSecretBinary());
        storedSecrets.add(loadMockDaoSecretCWithSecretBinary());
        when(mockDao.getAll())
                .thenReturn(SecretDocument.builder().secrets(storedSecrets).build());
        SecretManager sm = new SecretManager(mockAWSSecretClient, mockDao,mockKernelClient, localStoreMap);
        sm.syncFromCloud();

        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest request =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        request.setSecretId(SECRET_NAME_1);
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueResponse getSecretValueResult = sm.getSecret(request);

        assertEquals(SECRET_VALUE_1, getSecretValueResult.getSecretValue().getSecretString());
        assertNull(getSecretValueResult.getSecretValue().getSecretBinary());

        request = new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        request.setSecretId(SECRET_NAME_2);
        getSecretValueResult = sm.getSecret(request);

        assertNull(getSecretValueResult.getSecretValue().getSecretString());
        assertArrayEquals(SECRET_VALUE_BINARY_2, getSecretValueResult.getSecretValue().getSecretBinary());

        request = new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        request.setSecretId(SECRET_NAME_3);
        getSecretValueResult = sm.getSecret(request);

        assertNull(getSecretValueResult.getSecretValue().getSecretString());
        assertArrayEquals(SECRET_VALUE_BINARY_3, getSecretValueResult.getSecretValue().getSecretBinary());
    }

    @Test
    void GIVEN_secret_manager_WHEN_sync_from_cloud_with_partial_arn_THEN_secrets_are_loaded() throws Exception {
        getMockSecretsWithPartialArn();
        when(mockAWSSecretClient.getSecret(any())).thenReturn(getMockSecretA()).thenReturn(getMockSecretB());
        List<AWSSecretResponse> storedSecrets = new ArrayList<>();
        storedSecrets.add(loadMockDaoSecretA());
        when(mockDao.getAll()).thenReturn(SecretDocument.builder().secrets(storedSecrets).build());
        SecretManager sm = new SecretManager(mockAWSSecretClient, mockDao, mockKernelClient, localStoreMap);
        sm.syncFromCloud();

        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest request =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        request.setSecretId(SECRET_NAME_1);
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueResponse getSecretValueResult = sm.getSecret(request);

        assertArrayEquals(SECRET_VALUE_BINARY_1, getSecretValueResult.getSecretValue().getSecretBinary());
        assertEquals(ARN_1, getSecretValueResult.getSecretId());
        assertEquals(SECRET_VERSION_1, getSecretValueResult.getVersionId());
        assertEquals(2, getSecretValueResult.getVersionStage().size());
        assertEquals(LATEST_LABEL, getSecretValueResult.getVersionStage().get(0));
        assertEquals(SECRET_LABEL_1, getSecretValueResult.getVersionStage().get(1));
    }

    @Test
    void GIVEN_secret_manager_WHEN_ipc_req_with_refresh_throws_ex_THEN_load_from_cache(ExtensionContext context)
            throws Exception {
        loadMockSecrets();
        ignoreExceptionOfType(context, SecretManagerException.class);
        when(mockAWSSecretClient.getSecret(any())).thenReturn(getMockSecretA()).thenReturn(getMockSecretB());
        List<AWSSecretResponse> storedSecrets = new ArrayList<>();
        storedSecrets.add(loadMockDaoSecretA());
        when(mockDao.getAll()).thenReturn(SecretDocument.builder().secrets(storedSecrets).build());
        SecretManager sm = new SecretManager(mockAWSSecretClient, mockDao, mockKernelClient, localStoreMap);
        sm.syncFromCloud();

        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest request =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();

        request.setSecretId(SECRET_NAME_1);
        request.setRefresh(true);

        when(mockAWSSecretClient.getSecret(any())).thenThrow(SecretManagerException.class);
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueResponse response = sm.getSecret(request);

        assertArrayEquals(SECRET_VALUE_BINARY_1, response.getSecretValue().getSecretBinary());
        assertEquals(ARN_1, response.getSecretId());
        assertEquals(SECRET_VERSION_1, response.getVersionId());
        assertEquals(2, response.getVersionStage().size());
        assertEquals(LATEST_LABEL, response.getVersionStage().get(0));
        assertEquals(SECRET_LABEL_1, response.getVersionStage().get(1));
    }

    @Test
    void GIVEN_secret_manager_WHEN_sync_from_cloud_THEN_secrets_are_loaded() throws Exception {
        loadMockSecrets();
        when(mockAWSSecretClient.getSecret(any())).thenReturn(getMockSecretA()).thenReturn(getMockSecretB());
        List<AWSSecretResponse> storedSecrets = new ArrayList<>();
        storedSecrets.add(loadMockDaoSecretA());
        storedSecrets.add(loadMockDaoSecretB());
        when(mockDao.getAll()).thenReturn(SecretDocument.builder().secrets(storedSecrets).build());
        SecretManager sm = new SecretManager(mockAWSSecretClient, mockDao, mockKernelClient, localStoreMap);
        sm.syncFromCloud();

        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest request =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        request.setSecretId(SECRET_NAME_1);
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueResponse getSecretValueResult = sm.getSecret(request);

        assertArrayEquals(SECRET_VALUE_BINARY_1, getSecretValueResult.getSecretValue().getSecretBinary());
        assertEquals(ARN_1, getSecretValueResult.getSecretId());
        assertEquals(SECRET_VERSION_1, getSecretValueResult.getVersionId());
        assertEquals(2, getSecretValueResult.getVersionStage().size());
        assertEquals(LATEST_LABEL, getSecretValueResult.getVersionStage().get(0));
        assertEquals(SECRET_LABEL_1, getSecretValueResult.getVersionStage().get(1));

        request = new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        request.setSecretId(SECRET_NAME_2);
        getSecretValueResult = sm.getSecret(request);

        assertArrayEquals(SECRET_VALUE_BINARY_2, getSecretValueResult.getSecretValue().getSecretBinary());
        assertEquals(ARN_2, getSecretValueResult.getSecretId());
        assertEquals(SECRET_VERSION_2, getSecretValueResult.getVersionId());
        assertEquals(2, getSecretValueResult.getVersionStage().size());
        assertEquals(LATEST_LABEL, getSecretValueResult.getVersionStage().get(0));
        assertEquals(SECRET_LABEL_2, getSecretValueResult.getVersionStage().get(1));

        // Make a request with a label
        request = new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        request.setSecretId(SECRET_NAME_1);
        request.setVersionStage(SECRET_LABEL_1);
        getSecretValueResult = sm.getSecret(request);

        assertArrayEquals(SECRET_VALUE_BINARY_1, getSecretValueResult.getSecretValue().getSecretBinary());
        assertEquals(ARN_1, getSecretValueResult.getSecretId());
        assertEquals(SECRET_VERSION_1, getSecretValueResult.getVersionId());
        assertEquals(2, getSecretValueResult.getVersionStage().size());
        assertEquals(LATEST_LABEL, getSecretValueResult.getVersionStage().get(0));
        assertEquals(SECRET_LABEL_1, getSecretValueResult.getVersionStage().get(1));

        request = new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        request.setSecretId(SECRET_NAME_2);
        request.setVersionStage(SECRET_LABEL_2);
        getSecretValueResult = sm.getSecret(request);

        assertArrayEquals(SECRET_VALUE_BINARY_2, getSecretValueResult.getSecretValue().getSecretBinary());
        assertEquals(ARN_2, getSecretValueResult.getSecretId());
        assertEquals(SECRET_VERSION_2, getSecretValueResult.getVersionId());
        assertEquals(2, getSecretValueResult.getVersionStage().size());
        assertEquals(LATEST_LABEL, getSecretValueResult.getVersionStage().get(0));
        assertEquals(SECRET_LABEL_2, getSecretValueResult.getVersionStage().get(1));

        // Make a request with version id now
        request = new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        request.setSecretId(SECRET_NAME_1);
        request.setVersionId(SECRET_VERSION_1);
        getSecretValueResult = sm.getSecret(request);

        assertArrayEquals(SECRET_VALUE_BINARY_1, getSecretValueResult.getSecretValue().getSecretBinary());
        assertEquals(ARN_1, getSecretValueResult.getSecretId());
        assertEquals(SECRET_VERSION_1, getSecretValueResult.getVersionId());
        assertEquals(2, getSecretValueResult.getVersionStage().size());
        assertEquals(LATEST_LABEL, getSecretValueResult.getVersionStage().get(0));
        assertEquals(SECRET_LABEL_1, getSecretValueResult.getVersionStage().get(1));

        request = new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        request.setSecretId(SECRET_NAME_2);
        request.setVersionId(SECRET_VERSION_2);
        getSecretValueResult = sm.getSecret(request);

        assertArrayEquals(SECRET_VALUE_BINARY_2, getSecretValueResult.getSecretValue().getSecretBinary());
        assertEquals(ARN_2, getSecretValueResult.getSecretId());
        assertEquals(SECRET_VERSION_2, getSecretValueResult.getVersionId());
        assertEquals(2, getSecretValueResult.getVersionStage().size());
        assertEquals(LATEST_LABEL, getSecretValueResult.getVersionStage().get(0));
        assertEquals(SECRET_LABEL_2, getSecretValueResult.getVersionStage().get(1));
    }

    @Test
    void GIVEN_secret_manager_WHEN_sync_from_cloud_THEN_v1_secret_api_works() throws Exception {
        loadMockSecrets();
        when(mockAWSSecretClient.getSecret(any())).thenReturn(getMockSecretAWithSecretString())
                .thenReturn(getMockSecretBWithSecretBinary());
        List<AWSSecretResponse> storedSecrets = new ArrayList<>();
        storedSecrets.add(loadMockDaoSecretAWithSecretString());
        storedSecrets.add(loadMockDaoSecretBWithSecretBinary());
        when(mockDao.getAll()).thenReturn(SecretDocument.builder().secrets(storedSecrets).build());
        SecretManager sm = new SecretManager(mockAWSSecretClient, mockDao, mockKernelClient, localStoreMap);
        sm.syncFromCloud();

        com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest request =
                com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest.builder().secretId(SECRET_NAME_1)
                        .build();
        com.aws.greengrass.secretmanager.model.v1.GetSecretValueResult getSecretValueResult = sm.getSecret(request);

        assertEquals(SECRET_VALUE_1, getSecretValueResult.getSecretString());
        assertEquals(Date.from(SECRET_DATE_1), getSecretValueResult.getCreatedDate());
        assertEquals(SECRET_NAME_1, getSecretValueResult.getName());
        assertEquals(ARN_1, getSecretValueResult.getArn());
        assertEquals(SECRET_VERSION_1, getSecretValueResult.getVersionId());
        assertEquals(2, getSecretValueResult.getVersionStages().size());
        assertThat(getSecretValueResult.getVersionStages(), hasItem(LATEST_LABEL));
        assertThat(getSecretValueResult.getVersionStages(), hasItem(SECRET_LABEL_1));

        request = com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest.builder().secretId(SECRET_NAME_2)
                .build();
        getSecretValueResult = sm.getSecret(request);

        assertEquals(ByteBuffer.wrap(SECRET_VALUE_BINARY_2), getSecretValueResult.getSecretBinary());
        assertEquals(Date.from(SECRET_DATE_2), getSecretValueResult.getCreatedDate());
        assertEquals(SECRET_NAME_2, getSecretValueResult.getName());
        assertEquals(ARN_2, getSecretValueResult.getArn());
        assertEquals(SECRET_VERSION_2, getSecretValueResult.getVersionId());
        assertEquals(2, getSecretValueResult.getVersionStages().size());
        assertThat(getSecretValueResult.getVersionStages(), hasItem(LATEST_LABEL));
        assertThat(getSecretValueResult.getVersionStages(), hasItem(SECRET_LABEL_2));

        // Make a request with a label
        request = com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest.builder().secretId(SECRET_NAME_1)
                .versionStage(SECRET_LABEL_1).build();
        getSecretValueResult = sm.getSecret(request);

        assertEquals(SECRET_VALUE_1, getSecretValueResult.getSecretString());
        assertEquals(Date.from(SECRET_DATE_1), getSecretValueResult.getCreatedDate());
        assertEquals(SECRET_NAME_1, getSecretValueResult.getName());
        assertEquals(ARN_1, getSecretValueResult.getArn());
        assertEquals(SECRET_VERSION_1, getSecretValueResult.getVersionId());
        assertEquals(2, getSecretValueResult.getVersionStages().size());
        assertThat(getSecretValueResult.getVersionStages(), hasItem(LATEST_LABEL));
        assertThat(getSecretValueResult.getVersionStages(), hasItem(SECRET_LABEL_1));

        request = com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest.builder().secretId(SECRET_NAME_2)
                .versionStage(SECRET_LABEL_2).build();
        getSecretValueResult = sm.getSecret(request);

        assertEquals(ByteBuffer.wrap(SECRET_VALUE_BINARY_2), getSecretValueResult.getSecretBinary());
        assertEquals(Date.from(SECRET_DATE_2), getSecretValueResult.getCreatedDate());
        assertEquals(SECRET_NAME_2, getSecretValueResult.getName());
        assertEquals(ARN_2, getSecretValueResult.getArn());
        assertEquals(SECRET_VERSION_2, getSecretValueResult.getVersionId());
        assertEquals(2, getSecretValueResult.getVersionStages().size());
        assertThat(getSecretValueResult.getVersionStages(), hasItem(LATEST_LABEL));
        assertThat(getSecretValueResult.getVersionStages(), hasItem(SECRET_LABEL_2));

        // Make a request with version id now
        request = com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest.builder().secretId(SECRET_NAME_1)
                .versionId(SECRET_VERSION_1).build();
        getSecretValueResult = sm.getSecret(request);

        assertEquals(SECRET_VALUE_1, getSecretValueResult.getSecretString());
        assertEquals(ARN_1, getSecretValueResult.getArn());
        assertEquals(SECRET_NAME_1, getSecretValueResult.getName());
        assertEquals(Date.from(SECRET_DATE_1), getSecretValueResult.getCreatedDate());
        assertEquals(SECRET_VERSION_1, getSecretValueResult.getVersionId());
        assertEquals(2, getSecretValueResult.getVersionStages().size());
        assertThat(getSecretValueResult.getVersionStages(), hasItem(LATEST_LABEL));
        assertThat(getSecretValueResult.getVersionStages(), hasItem(SECRET_LABEL_1));

        request = com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest.builder().secretId(SECRET_NAME_2)
                .versionId(SECRET_VERSION_2).build();
        getSecretValueResult = sm.getSecret(request);

        assertEquals(ByteBuffer.wrap(SECRET_VALUE_BINARY_2), getSecretValueResult.getSecretBinary());
        assertEquals(Date.from(SECRET_DATE_2), getSecretValueResult.getCreatedDate());
        assertEquals(SECRET_NAME_2, getSecretValueResult.getName());
        assertEquals(ARN_2, getSecretValueResult.getArn());
        assertEquals(SECRET_VERSION_2, getSecretValueResult.getVersionId());
        assertEquals(2, getSecretValueResult.getVersionStages().size());
        assertThat(getSecretValueResult.getVersionStages(), hasItem(LATEST_LABEL));
        assertThat(getSecretValueResult.getVersionStages(), hasItem(SECRET_LABEL_2));
    }


    @Test
    void GIVEN_secret_manager_WHEN_invalid_arn_THEN_secrets_are_not_loaded(ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, SecretManagerException.class);
        when(mockDao.getAll()).thenReturn(mock(SecretDocument.class));
        when(mockAWSSecretClient.getSecret(any())).thenReturn(getMockSecretA());
        SecretManager sm = new SecretManager(mockAWSSecretClient, mockDao,mockKernelClient, localStoreMap);
        String invalidArn = "randomArn";
        SecretConfiguration secret1 = SecretConfiguration.builder().arn(ARN_1).build();
        SecretConfiguration secret2 = SecretConfiguration.builder().arn(invalidArn)
                .labels(Arrays.asList(LATEST_LABEL, SECRET_LABEL_1)).build();
        List<SecretConfiguration> configuredSecrets = new ArrayList<SecretConfiguration>() {{
            add(secret1);
            add(secret2);
        }};
        Configuration config = new Configuration(new Context());
        config.lookupTopics("services", SecretManagerService.SECRET_MANAGER_SERVICE_NAME)
                .lookup(CONFIGURATION_CONFIG_KEY, SECRETS_TOPIC).withValueChecked(configuredSecrets);
        doReturn(config).when(mockKernelClient).getConfig();
        sm.syncFromCloud();

        // verify that we only called aws cloud for ARN_1 and skipped invalidArn
        verify(mockAWSSecretClient, times(1)).getSecret(awsClientRequestCaptor.capture());
        List<software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest> awsRequest =
                awsClientRequestCaptor.getAllValues();
        assertEquals(1, awsRequest.size());
        assertEquals(ARN_1, awsRequest.get(0).secretId());
    }

    @Test
    void GIVEN_secret_manager_WHEN_empty_secret_config_THEN_local_secrets_are_removed(ExtensionContext context)
            throws Exception {
        ignoreExceptionOfType(context, SecretManagerException.class);
        List<AWSSecretResponse> storedSecrets = new ArrayList<>();
        storedSecrets.add(loadMockDaoSecretA());
        when(mockDao.getAll()).thenReturn(SecretDocument.builder().secrets(storedSecrets).build());
        SecretManager sm = new SecretManager(mockAWSSecretClient, mockDao, mockKernelClient, localStoreMap);

        // Load one secret from local and verify
        sm.reloadCache();
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest request =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        request.setSecretId(SECRET_NAME_1);
        assertEquals(SECRET_VALUE_1, new String(sm.getSecret(request).getSecretValue().getSecretBinary()));

        Configuration config = new Configuration(new Context());
        config.lookupTopics("services", SecretManagerService.SECRET_MANAGER_SERVICE_NAME)
                .lookup(CONFIGURATION_CONFIG_KEY, SECRETS_TOPIC).withValueChecked(new ArrayList<>());
        doReturn(config).when(mockKernelClient).getConfig();
        // Now pass in empty config and assert no secret is saved
        sm.syncFromCloud();
        verify(mockDao, times(1)).saveAll(documentArgumentCaptor.capture());
        assertEquals(0, documentArgumentCaptor.getValue().getSecrets().size());

        // Load doc and assert secret removed
        when(mockDao.getAll()).thenReturn(documentArgumentCaptor.getValue());
        sm.reloadCache();
        try {
            sm.getSecret(request);
        } catch (GetSecretException e) {
            assertEquals("Secret not found " + SECRET_NAME_1, e.getMessage());
            assertEquals(404, e.getStatus());
        }
    }

    @Test
    void GIVEN_secret_manager_WHEN_cloud_errors_THEN_secrets_are_not_loaded(ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, SecretManagerException.class);
        ignoreExceptionOfType(context, IOException.class);
        loadMockSecrets();
        when(mockDao.getAll()).thenReturn(mock(SecretDocument.class));
        when(mockAWSSecretClient.getSecret(any())).thenThrow(SecretManagerException.class);
        SecretManager sm = new SecretManager(mockAWSSecretClient, mockDao,  mockKernelClient, localStoreMap);
        // Secrets should not be loaded as the secret fails and should throw SecretManagerException
        sm.syncFromCloud();
        verify(mockAWSSecretClient, times(4)).getSecret(any());
        verify(mockDao, times(0)).saveAll(any());

        // Now, update the aws client to return a result and then throw SecretManagerException for second secret
        // Secrets should not be loaded as one secret fails and should throw SecretManagerException
        reset(mockAWSSecretClient);
        reset(mockDao);
        when(mockDao.getAll()).thenReturn(mock(SecretDocument.class));
        when(mockAWSSecretClient.getSecret(any())).thenReturn(getMockSecretA()).thenThrow(SecretManagerException.class);
        sm.syncFromCloud();

        verify(mockAWSSecretClient, times(4)).getSecret(any());
        verify(mockDao, times(1)).saveAll(any());

        // Now, update the aws client to return a result and then throw IOException for second secret
        // Secrets should not be loaded as one secret fails and should throw SecretManagerException
        reset(mockAWSSecretClient);
        reset(mockDao);
        when(mockDao.getAll()).thenReturn(mock(SecretDocument.class));

        when(mockAWSSecretClient.getSecret(any())).thenReturn(getMockSecretA()).thenReturn(getMockSecretB());
        sm.syncFromCloud();
        verify(mockAWSSecretClient, times(4)).getSecret(any());
        verify(mockDao, times(2)).saveAll(any());
    }

    @Test
    void GIVEN_secret_manager_WHEN_network_error_and_new_secret_THEN_throws(ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, SecretManagerException.class);
        when(mockDao.getAll()).thenReturn(SecretDocument.builder().secrets(Collections.singletonList(loadMockDaoSecretA())).build());
        SecretManager sm = new SecretManager(mockAWSSecretClient, mockDao, mockKernelClient, localStoreMap);
        SecretConfiguration secret1 = SecretConfiguration.builder().arn(ARN_1).build();
        Configuration config = new Configuration(new Context());
        config.lookupTopics("services", SecretManagerService.SECRET_MANAGER_SERVICE_NAME)
                .lookup(CONFIGURATION_CONFIG_KEY, SECRETS_TOPIC).withValueChecked(Collections.singletonList(secret1));
        doReturn(config).when(mockKernelClient).getConfig();
        when(mockAWSSecretClient.getSecret(any())).thenThrow(SecretManagerException.class);
        sm.syncFromCloud();
        verify(mockDao, times(0)).saveAll(any());
    }

    @Test
    void GIVEN_secret_manager_WHEN_network_error_and_existing_secret_THEN_not_throw(ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, SecretManagerException.class);
        loadMockSecrets();
        when(mockDao.getAll()).thenReturn(SecretDocument.builder().secrets(Collections.singletonList(loadMockDaoSecretA())).build());

        SecretManager sm = new SecretManager(mockAWSSecretClient, mockDao, mockKernelClient, localStoreMap);

        // Secret is in Dao, IOException is ignored and secret is loaded from local
        when(mockAWSSecretClient.getSecret(any())).thenThrow(SecretManagerException.class);
        sm.syncFromCloud();
        verify(mockDao, times(0)).saveAll(any());
    }

    @Test
    void GIVEN_secret_manager_WHEN_some_label_error_THEN_throws_for_non_network_error(ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, IOException.class);
        ignoreExceptionOfType(context, SecretManagerException.class);

        SecretManager sm = new SecretManager(mockAWSSecretClient, mockDao, mockKernelClient, localStoreMap);
        SecretConfiguration secret =
                SecretConfiguration.builder().arn(ARN_2).labels(Arrays.asList(LATEST_LABEL, SECRET_LABEL_1)).build();
        Configuration config = new Configuration(new Context());
        config.lookupTopics("services", SecretManagerService.SECRET_MANAGER_SERVICE_NAME)
                .lookup(CONFIGURATION_CONFIG_KEY, SECRETS_TOPIC).withValueChecked(Collections.singletonList(secret));
        doReturn(config).when(mockKernelClient).getConfig();
        // two labels both throw IOException
        // Given only the first one label is in Dao, IOException is ignored and SecretManagerException is thrown
        when(mockDao.getAll()).thenReturn(SecretDocument.builder().secrets(Arrays.asList(loadMockDaoSecretB())).build());
        when(mockAWSSecretClient.getSecret(any())).thenThrow(SecretManagerException.class).thenThrow(SecretManagerException.class);
        sm.syncFromCloud();
        // No updates from cloud, then do not update local store
        verify(mockDao, times(0)).saveAll(documentArgumentCaptor.capture());
        reset(mockAWSSecretClient);
        reset(mockDao);
        AWSSecretResponse secondSec =
                AWSSecretResponse.builder().name(SECRET_NAME_2).arn(ARN_2).createdDate(SECRET_DATE_2.toEpochMilli())
                .encryptedSecretString(ENCRYPTED_SECRET_2).encryptedSecretBinary(ENCRYPTED_SECRET_BINARY_2)
                .versionStages(Arrays.asList(SECRET_LABEL_1)).versionId(SECRET_VERSION_1)
                .build();
        // two labels throw IOException and SecretManagerException respectively.
        // Given both labels are in Dao, IOException is ignored and SecretManagerException is thrown
        when(mockDao.getAll()).thenReturn(SecretDocument.builder().secrets(Arrays.asList(loadMockDaoSecretB(), secondSec)).build());
        when(mockAWSSecretClient.getSecret(any())).thenThrow(SecretManagerException.class).thenThrow(SecretManagerException.class);
        sm.syncFromCloud();
        verify(mockDao, times(0)).saveAll(documentArgumentCaptor.capture());
        reset(mockAWSSecretClient);
        reset(mockDao);
        // one label succeeds and the other throws IOException and SecretManagerException respectively.
        // Given both labels are in Dao, IOException is ignored and SecretManagerException is thrown
        when(mockDao.getAll()).thenReturn(SecretDocument.builder().secrets(Arrays.asList(loadMockDaoSecretB(), secondSec)).build());

        when(mockAWSSecretClient.getSecret(any())).thenReturn(getMockSecretB()).thenThrow(SecretManagerException.class);
        sm.syncFromCloud();
        // Only one update from cloud
        verify(mockDao, times(1)).saveAll(documentArgumentCaptor.capture());
        assertEquals(2, documentArgumentCaptor.getValue().getSecrets().size());

        reset(mockDao);
        // one label succeeds and the other throws IOException and SecretManagerException respectively.
        // Given both labels are in Dao, IOException is ignored and secret is loaded from local
        when(mockDao.getAll()).thenReturn(SecretDocument.builder().secrets(Arrays.asList(loadMockDaoSecretB(), secondSec)).build());
        sm.syncFromCloud();
        verify(mockDao, times(0)).saveAll(documentArgumentCaptor.capture());
    }


    @Test
    void GIVEN_secret_manager_WHEN_load_from_disk_fails_THEN_throws(ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, SecretManagerException.class);

        loadMockSecrets();
        doThrow(SecretManagerException.class).when(mockDao).getAll();

        SecretManager sm = new SecretManager(mockAWSSecretClient, mockDao, mockKernelClient, localStoreMap);
        assertThrows(SecretManagerException.class, sm::reloadCache);
        assertThrows(RuntimeException.class, sm::syncFromCloud);
    }

    @Test
    void GIVEN_secret_manager_WHEN_unable_to_decrypt_THEN_load_from_disk_doesnt_throw(ExtensionContext context)
            throws Exception {
        ignoreExceptionOfType(context, SecretCryptoException.class);
        AWSSecretResponse mockSecret = mock(AWSSecretResponse.class);
        when(mockSecret.getArn()).thenReturn(ARN_1);
        when(mockSecret.getName()).thenReturn(SECRET_NAME_1);
        when(mockSecret.getEncryptedSecretString()).thenReturn(Base64.getEncoder().encodeToString("test".getBytes()));
        List<AWSSecretResponse> listSecrets = new ArrayList<>();
        listSecrets.add(mockSecret);
        SecretDocument diskSecrets = SecretDocument.builder().secrets(listSecrets).build();
        when(mockDao.getAll()).thenReturn(diskSecrets);

        SecretManager sm = new SecretManager(mockAWSSecretClient, mockDao, mockKernelClient, localStoreMap);
        // This will throw as encrypted string is invalid format for crypter
        sm.reloadCache();
    }

    @Test
    void GIVEN_secret_manager_WHEN_sync_from_cloud_THEN_default_label_always_downloaded(ExtensionContext context)
            throws Exception {
        loadMockSecrets();
        ignoreExceptionOfType(context, SecretManagerException.class);
        when(mockDao.getAll()).thenReturn(mock(SecretDocument.class));
        when(mockAWSSecretClient.getSecret(awsClientRequestCaptor.capture())).thenReturn(getMockSecretA())
                .thenReturn(getMockSecretB());

        SecretManager sm = new SecretManager(mockAWSSecretClient, mockDao, mockKernelClient, localStoreMap);
        sm.syncFromCloud();
        verify(mockDao, times(2)).saveAll(documentArgumentCaptor.capture());

        List<software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest> awsRequests =
                awsClientRequestCaptor.getAllValues();
        assertEquals(4, awsRequests.size());
        assertEquals(3, awsRequests.stream().filter(r->r.versionStage().equals(LATEST_LABEL)).count());
    }

    @Test
    void GIVEN_secret_manager_WHEN_get_called_with_invalid_request_THEN_proper_errors_are_returned() throws Exception {
        loadMockSecrets();
        SecretManager sm = new SecretManager(mockAWSSecretClient,mockDao,mockKernelClient, localStoreMap);
        when(mockDao.getAll()).thenReturn(SecretDocument.builder().secrets(new ArrayList<>()).build());
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest request =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        try {
            sm.getSecret(request);
        } catch (GetSecretException response) {
            assertEquals(400, response.getStatus());
            assertEquals("SecretId absent in the request", response.getMessage());
        }

        // Create a request for secret which is not present
        request = new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        request.setSecretId(SECRET_NAME_1);
        try {
            sm.getSecret(request);
        } catch (GetSecretException response) {
            assertEquals(404, response.getStatus());
            assertEquals("Secret not found " + SECRET_NAME_1, response.getMessage());
        }

        // Create a request for secret arn which is not present
        request = new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        request.setSecretId(ARN_1);
        try {
            sm.getSecret(request);
        } catch (GetSecretException response) {
            assertEquals(404, response.getStatus());
            assertEquals("Secret not found " + ARN_1, response.getMessage());
        }

        // Actually load the secrets
        when(mockAWSSecretClient.getSecret(any())).thenReturn(getMockSecretA()).thenReturn(getMockSecretB());
        List<AWSSecretResponse> storedSecrets = new ArrayList<>();
        storedSecrets.add(loadMockDaoSecretA());
        storedSecrets.add(loadMockDaoSecretB());
        when(mockDao.getAll()).thenReturn(SecretDocument.builder().secrets(storedSecrets).build());
        sm.syncFromCloud();

        // Create a request for secret with both version and label
        request = new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        request.setSecretId(SECRET_NAME_1);
        request.setVersionId(SECRET_VERSION_1);
        request.setVersionStage(SECRET_LABEL_1);
        try {
            sm.getSecret(request);
        } catch (GetSecretException response) {
            assertEquals(400, response.getStatus());
            assertEquals("Both versionId and Stage are set in the request", response.getMessage());
        }

        // Create a request for secret with an invalid version
        String invalidVersion = "InvalidVersion";
        request = new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        request.setSecretId(SECRET_NAME_1);
        request.setVersionId(invalidVersion);
        try {
            sm.getSecret(request);
        } catch (GetSecretException response) {
            assertEquals(404, response.getStatus());
            assertEquals("Version Id " + invalidVersion + " not found for secret " + SECRET_NAME_1,
                    response.getMessage());
        }

        // Create a request for secret with an invalid label
        String invalidLabel = "InvalidLabel";
        request = new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        request.setSecretId(SECRET_NAME_1);
        request.setVersionStage(invalidLabel);
        try {
            sm.getSecret(request);
        } catch (GetSecretException response) {
            assertEquals(404, response.getStatus());
            assertEquals("Version stage " + invalidLabel + " not found for secret " + SECRET_NAME_1,
                    response.getMessage());
        }
    }
}
