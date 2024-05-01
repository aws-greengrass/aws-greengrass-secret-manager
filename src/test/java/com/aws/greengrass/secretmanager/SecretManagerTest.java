/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager;

import com.aws.greengrass.config.Configuration;
import com.aws.greengrass.config.Topic;
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
import com.aws.greengrass.security.SecurityService;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import com.aws.greengrass.util.EncryptionUtils;
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
import java.net.URI;
import java.net.URISyntaxException;
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

import static com.aws.greengrass.testcommons.testutilities.ExceptionLogProtector.ignoreExceptionOfType;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
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
    private static final Instant SECRET_DATE_1 = Instant.now();
    private static final Instant SECRET_DATE_2 = Instant.now();

    private static final String ARN_1 = "arn:aws:secretsmanager:us-east-1:999936977227:secret:randomSecret-74lYJh";
    private static final String ARN_2 = "arn:aws:secretsmanager:us-east-1:111136977227:secret:shhhhh-32lYsd";
    private static final String ARN_3 = "arn:aws-us-gov:secretsmanager:us-east-1:111136977227:secret:shhhhh-32lYsd";
    private static final String PARTIAL_ARN = "arn:aws:secretsmanager:us-east-1:999936977227:secret:randomSecret";

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
    private FileSecretDao mockDao;

    @Mock
    private KernelClient mockKernelClient;

    private final SecurityService mockSecurityService = spy(new SecurityService(mock(DeviceConfiguration.class)));

    private final ExecutorService executorService = Executors.newSingleThreadExecutor();

    @Captor
    ArgumentCaptor<SecretDocument> documentArgumentCaptor;

    @Captor
    ArgumentCaptor<software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest> awsClientRequestCaptor;

    private List<SecretConfiguration> getMockSecrets() {
        SecretConfiguration secret1 = SecretConfiguration.builder().arn(ARN_1).build();
        SecretConfiguration secret2 = SecretConfiguration.builder().arn(ARN_2)
                .labels(Arrays.asList(LATEST_LABEL, SECRET_LABEL_1)).build();
        SecretConfiguration secret3 = SecretConfiguration.builder().arn(ARN_3).build();
        return new ArrayList<SecretConfiguration>() {{
            add(secret1);
            add(secret2);
            add(secret3);
        }};
    }

    private List<SecretConfiguration> getMockSecretsWithPartialArn() {
        SecretConfiguration secret = SecretConfiguration.builder().arn(PARTIAL_ARN).build();
        return new ArrayList<SecretConfiguration>() {{
            add(secret);
        }};
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

    private AWSSecretResponse getMockDaoSecretA() {
        return AWSSecretResponse.builder().name(SECRET_NAME_1).arn(ARN_1).createdDate(SECRET_DATE_1.toEpochMilli())
                .encryptedSecretString(ENCRYPTED_SECRET_1).encryptedSecretBinary(ENCRYPTED_SECRET_BINARY_1)
                .versionStages(Arrays.asList(LATEST_LABEL, SECRET_LABEL_1)).versionId(SECRET_VERSION_1)
                .build();
    }

    private AWSSecretResponse getMockDaoSecretB() {
        return AWSSecretResponse.builder().name(SECRET_NAME_2).arn(ARN_2).createdDate(SECRET_DATE_2.toEpochMilli())
                .encryptedSecretString(ENCRYPTED_SECRET_2).encryptedSecretBinary(ENCRYPTED_SECRET_BINARY_2)
                .versionStages(Arrays.asList(LATEST_LABEL, SECRET_LABEL_2)).versionId(SECRET_VERSION_2)
                .build();
    }

    private AWSSecretResponse getMockDaoSecretAWithSecretString() {
        return AWSSecretResponse.builder().name(SECRET_NAME_1).arn(ARN_1).createdDate(SECRET_DATE_1.toEpochMilli())
                .encryptedSecretString(ENCRYPTED_SECRET_1)
                .versionStages(Arrays.asList(LATEST_LABEL, SECRET_LABEL_1)).versionId(SECRET_VERSION_1)
                .build();
    }

    private AWSSecretResponse getMockDaoSecretBWithSecretBinary() {
        return AWSSecretResponse.builder().name(SECRET_NAME_2).arn(ARN_2).createdDate(SECRET_DATE_2.toEpochMilli())
                .encryptedSecretBinary(ENCRYPTED_SECRET_BINARY_2)
                .versionStages(Arrays.asList(LATEST_LABEL, SECRET_LABEL_2)).versionId(SECRET_VERSION_2)
                .build();
    }

    private AWSSecretResponse getMockDaoSecretCWithSecretBinary() {
        return AWSSecretResponse.builder().name(SECRET_NAME_3).arn(ARN_3).createdDate(SECRET_DATE_2.toEpochMilli())
                .encryptedSecretBinary(ENCRYPTED_SECRET_BINARY_3)
                .versionStages(Arrays.asList(LATEST_LABEL, SECRET_LABEL_2)).versionId(SECRET_VERSION_2)
                .build();
    }

    @Test
    void GIVEN_cloud_secret_WHEN_binary_secret_set_THEN_only_binary_returned() throws Exception {
        when(mockAWSSecretClient.getSecret(any()))
                .thenReturn(getMockSecretAWithSecretString())
                .thenReturn(getMockSecretBWithSecretBinary())
                .thenReturn(getMockSecretCWithSecretBinary());
        List<AWSSecretResponse> storedSecrets = new ArrayList<>();
        storedSecrets.add(getMockDaoSecretAWithSecretString());
        storedSecrets.add(getMockDaoSecretBWithSecretBinary());
        storedSecrets.add(getMockDaoSecretCWithSecretBinary());
        when(mockDao.getAll()).thenReturn(SecretDocument.builder().secrets(storedSecrets).build());
        SecretManager sm = new SecretManager(mockAWSSecretClient, crypter, mockDao);
        sm.syncFromCloud(getMockSecrets());

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
        when(mockAWSSecretClient.getSecret(any())).thenReturn(getMockSecretA()).thenReturn(getMockSecretB());
        List<AWSSecretResponse> storedSecrets = new ArrayList<>();
        storedSecrets.add(getMockDaoSecretA());
        when(mockDao.getAll()).thenReturn(SecretDocument.builder().secrets(storedSecrets).build());
        SecretManager sm = new SecretManager(mockAWSSecretClient, crypter, mockDao);
        sm.syncFromCloud(getMockSecretsWithPartialArn());

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
    void GIVEN_secret_manager_WHEN_sync_from_cloud_THEN_secrets_are_loaded() throws Exception {
        when(mockAWSSecretClient.getSecret(any())).thenReturn(getMockSecretA()).thenReturn(getMockSecretB());
        List<AWSSecretResponse> storedSecrets = new ArrayList<>();
        storedSecrets.add(getMockDaoSecretA());
        storedSecrets.add(getMockDaoSecretB());
        when(mockDao.getAll()).thenReturn(SecretDocument.builder().secrets(storedSecrets).build());
        SecretManager sm = new SecretManager(mockAWSSecretClient, crypter, mockDao);
        sm.syncFromCloud(getMockSecrets());

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
        when(mockAWSSecretClient.getSecret(any())).thenReturn(getMockSecretAWithSecretString())
                .thenReturn(getMockSecretBWithSecretBinary());
        List<AWSSecretResponse> storedSecrets = new ArrayList<>();
        storedSecrets.add(getMockDaoSecretAWithSecretString());
        storedSecrets.add(getMockDaoSecretBWithSecretBinary());
        when(mockDao.getAll()).thenReturn(SecretDocument.builder().secrets(storedSecrets).build());
        SecretManager sm = new SecretManager(mockAWSSecretClient, crypter, mockDao);
        sm.syncFromCloud(getMockSecrets());

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
        SecretManager sm = new SecretManager(mockAWSSecretClient, mockSecurityService, mockDao, executorService);
        String invalidArn = "randomArn";
        SecretConfiguration secret1 = SecretConfiguration.builder().arn(ARN_1).build();
        SecretConfiguration secret2 = SecretConfiguration.builder().arn(invalidArn)
                .labels(Arrays.asList(LATEST_LABEL, SECRET_LABEL_1)).build();
        List<SecretConfiguration> configuredSecrets = new ArrayList<SecretConfiguration>() {{
            add(secret1);
            add(secret2);
        }};
        sm.syncFromCloud(configuredSecrets);

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
        storedSecrets.add(getMockDaoSecretA());
        when(mockDao.getAll()).thenReturn(SecretDocument.builder().secrets(storedSecrets).build());
        SecretManager sm = new SecretManager(mockAWSSecretClient, mockSecurityService, mockDao, executorService);

        sm.waitForInitialization();
        // Load one secret from local and verify
        sm.loadSecretsFromLocalStore();
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest request =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        request.setSecretId(SECRET_NAME_1);
        System.out.println(sm.getSecret(request).getSecretId());
        assertEquals(SECRET_VALUE_1, new String(sm.getSecret(request).getSecretValue().getSecretBinary()));

        // Now pass in empty config and assert no secret is saved
        sm.syncFromCloud(new ArrayList<>());
        verify(mockDao, times(1)).saveAll(documentArgumentCaptor.capture());
        assertEquals(0, documentArgumentCaptor.getValue().getSecrets().size());

        // Load doc and assert secret removed
        when(mockDao.getAll()).thenReturn(documentArgumentCaptor.getValue());
        sm.loadSecretsFromLocalStore();
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
        when(mockDao.getAll()).thenReturn(mock(SecretDocument.class));
        when(mockAWSSecretClient.getSecret(any())).thenThrow(SecretManagerException.class);
        SecretManager sm = new SecretManager(mockAWSSecretClient, mockSecurityService, mockDao, executorService);
        // Secrets should not be loaded as the secret fails and should throw SecretManagerException
        assertThrows(SecretManagerException.class, () -> sm.syncFromCloud(getMockSecrets()));
        verify(mockAWSSecretClient, times(1)).getSecret(any());
        verify(mockDao, times(0)).saveAll(any());

        // Now, update the aws client to return a result and then throw SecretManagerException for second secret
        // Secrets should not be loaded as one secret fails and should throw SecretManagerException
        reset(mockAWSSecretClient);
        reset(mockDao);
        when(mockAWSSecretClient.getSecret(any())).thenReturn(getMockSecretA()).thenThrow(SecretManagerException.class);
        assertThrows(SecretManagerException.class, () -> sm.syncFromCloud(getMockSecrets()));
        verify(mockAWSSecretClient, times(2)).getSecret(any());
        verify(mockDao, times(0)).saveAll(any());

        // Now, update the aws client to return a result and then throw IOException for second secret
        // Secrets should not be loaded as one secret fails and should throw SecretManagerException
        reset(mockAWSSecretClient);
        reset(mockDao);
        when(mockAWSSecretClient.getSecret(any())).thenReturn(getMockSecretA()).thenThrow(IOException.class);
        assertThrows(SecretManagerException.class, () -> sm.syncFromCloud(getMockSecrets()));
        verify(mockAWSSecretClient, times(2)).getSecret(any());
        verify(mockDao, times(0)).saveAll(any());
    }

    @Test
    void GIVEN_secret_manager_WHEN_network_error_and_new_secret_THEN_throws() throws Exception {
        SecretManager sm = new SecretManager(mockAWSSecretClient, mockSecurityService, mockDao, executorService);
        SecretConfiguration secret1 = SecretConfiguration.builder().arn(ARN_1).build();
        List<SecretConfiguration> configuredSecret1 = Collections.singletonList(secret1);

        when(mockAWSSecretClient.getSecret(any())).thenThrow(IOException.class);
        assertThrows(SecretManagerException.class, () -> sm.syncFromCloud(configuredSecret1));
    }

    @Test
    void GIVEN_secret_manager_WHEN_network_error_and_existing_secret_THEN_not_throw() throws Exception {
        when(mockDao.getAll()).thenReturn(mock(SecretDocument.class));
        SecretManager sm = new SecretManager(mockAWSSecretClient, mockSecurityService, mockDao, executorService);
        SecretConfiguration secret1 = SecretConfiguration.builder().arn(ARN_1).build();
        List<SecretConfiguration> configuredSecret1 = Collections.singletonList(secret1);

        // Secret is in Dao, IOException is ignored and secret is loaded from local
        when(mockDao.get(ARN_1, LATEST_LABEL)).thenReturn(getMockDaoSecretA());
        when(mockAWSSecretClient.getSecret(any())).thenThrow(IOException.class);
        sm.syncFromCloud(configuredSecret1);
        verify(mockDao, times(1)).saveAll(documentArgumentCaptor.capture());
        // Now assert that one secret was persisted in the db
        assertEquals(1, documentArgumentCaptor.getValue().getSecrets().size());
    }

    @Test
    void GIVEN_secret_manager_WHEN_some_label_error_THEN_throws_for_non_network_error() throws Exception {
        when(mockDao.getAll()).thenReturn(mock(SecretDocument.class));
        SecretManager sm = new SecretManager(mockAWSSecretClient, mockSecurityService, mockDao, executorService);
        SecretConfiguration secret =
                SecretConfiguration.builder().arn(ARN_2).labels(Arrays.asList(LATEST_LABEL, SECRET_LABEL_1)).build();
        List<SecretConfiguration> configuredSecret = Collections.singletonList(secret);

        // two labels both throw IOException
        // Given only the first one label is in Dao, IOException is ignored and SecretManagerException is thrown
        when(mockDao.get(ARN_2, LATEST_LABEL)).thenReturn(getMockDaoSecretB());
        when(mockDao.get(ARN_2, SECRET_LABEL_1)).thenReturn(null);
        when(mockAWSSecretClient.getSecret(any())).thenThrow(IOException.class).thenThrow(IOException.class);
        assertThrows(SecretManagerException.class, () -> sm.syncFromCloud(configuredSecret));

        reset(mockAWSSecretClient);
        reset(mockDao);
        when(mockDao.getAll()).thenReturn(mock(SecretDocument.class));
        // two labels throw IOException and SecretManagerException respectively.
        // Given both labels are in Dao, IOException is ignored and SecretManagerException is thrown
        when(mockDao.get(ARN_2, LATEST_LABEL)).thenReturn(getMockDaoSecretB());
        when(mockDao.get(ARN_2, SECRET_LABEL_1)).thenReturn(getMockDaoSecretB());
        when(mockAWSSecretClient.getSecret(any())).thenThrow(IOException.class).thenThrow(SecretManagerException.class);
        assertThrows(SecretManagerException.class, () -> sm.syncFromCloud(configuredSecret));

        reset(mockAWSSecretClient);
        reset(mockDao);
        when(mockDao.getAll()).thenReturn(mock(SecretDocument.class));
        // one label succeeds and the other throws IOException and SecretManagerException respectively.
        // Given both labels are in Dao, IOException is ignored and SecretManagerException is thrown
        when(mockDao.get(ARN_2, LATEST_LABEL)).thenReturn(getMockDaoSecretB());
        when(mockAWSSecretClient.getSecret(any())).thenReturn(getMockSecretB()).thenThrow(SecretManagerException.class);
        assertThrows(SecretManagerException.class, () -> sm.syncFromCloud(configuredSecret));

        reset(mockAWSSecretClient);
        reset(mockDao);
        when(mockDao.getAll()).thenReturn(mock(SecretDocument.class));
        // one label succeeds and the other throws IOException and SecretManagerException respectively.
        // Given both labels are in Dao, IOException is ignored and secret is loaded from local
        when(mockDao.get(ARN_2, LATEST_LABEL)).thenReturn(getMockDaoSecretB());
        when(mockAWSSecretClient.getSecret(any())).thenReturn(getMockSecretB()).thenThrow(IOException.class);
        sm.syncFromCloud(configuredSecret);
        verify(mockDao, times(1)).saveAll(documentArgumentCaptor.capture());
        // Now assert that both secret persisted in the db
        assertEquals(2, documentArgumentCaptor.getValue().getSecrets().size());
    }

    @Test
    void GIVEN_secret_manager_WHEN_load_from_disk_fails_THEN_throws() throws Exception {
        when(mockAWSSecretClient.getSecret(any())).thenReturn(getMockSecretA());
        doThrow(SecretManagerException.class).when(mockDao).getAll();

        SecretManager sm = new SecretManager(mockAWSSecretClient, mockSecurityService, mockDao, executorService);
        assertThrows(SecretManagerException.class, () -> sm.syncFromCloud(getMockSecrets()));
        assertThrows(SecretManagerException.class, sm::loadSecretsFromLocalStore);
    }

    @Test
    void GIVEN_secret_manager_WHEN_unable_to_decrypt_THEN_load_from_disk_throws(ExtensionContext context)
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

        SecretManager sm = new SecretManager(mockAWSSecretClient, mockSecurityService, mockDao, executorService);
        sm.waitForInitialization();
        // This will throw as encrypted string is invalid format for crypter
        assertThrows(SecretManagerException.class, sm::loadSecretsFromLocalStore);
    }

    @Test
    void GIVEN_secret_manager_WHEN_sync_from_cloud_THEN_default_label_always_downloaded(ExtensionContext context)
            throws Exception {
        ignoreExceptionOfType(context, SecretManagerException.class);
        when(mockDao.getAll()).thenReturn(mock(SecretDocument.class));
        when(mockAWSSecretClient.getSecret(awsClientRequestCaptor.capture())).thenReturn(getMockSecretA())
                .thenReturn(getMockSecretB());
        SecretManager sm = new SecretManager(mockAWSSecretClient, mockSecurityService, mockDao, executorService);
        sm.syncFromCloud(getMockSecrets());
        verify(mockDao, times(1)).saveAll(documentArgumentCaptor.capture());

        List<software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest> awsRequests =
                awsClientRequestCaptor.getAllValues();
        assertEquals(4, awsRequests.size());
        assertEquals(LATEST_LABEL, awsRequests.get(0).versionStage());
        assertEquals(ARN_1, awsRequests.get(0).secretId());
        assertEquals(SECRET_LABEL_1, awsRequests.get(1).versionStage());
        assertEquals(ARN_2, awsRequests.get(2).secretId());
        assertEquals(LATEST_LABEL, awsRequests.get(2).versionStage());
        assertEquals(ARN_2, awsRequests.get(2).secretId());
        assertEquals(LATEST_LABEL, awsRequests.get(3).versionStage());
        assertEquals(ARN_3, awsRequests.get(3).secretId());
    }

    @Test
    void GIVEN_secret_manager_WHEN_invalid_key_THEN_secret_manager_not_instantiated() throws URISyntaxException {
        reset(mockKernelClient);
        when(mockSecurityService.getDeviceIdentityPrivateKeyURI()).thenReturn(new URI("file:///tmp"));
        SecretManager manager = new SecretManager(mockAWSSecretClient, mockSecurityService, mockDao, executorService);
        assertThrows(SecretCryptoException.class, manager::waitForInitialization);
    }

    @Test
    void GIVEN_secret_manager_WHEN_get_called_with_invalid_request_THEN_proper_errors_are_returned() throws Exception {
        SecretManager sm = new SecretManager(mockAWSSecretClient, crypter, mockDao);
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
        storedSecrets.add(getMockDaoSecretA());
        storedSecrets.add(getMockDaoSecretB());
        when(mockDao.getAll()).thenReturn(SecretDocument.builder().secrets(storedSecrets).build());
        sm.syncFromCloud(getMockSecrets());

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
