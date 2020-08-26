package com.aws.iot.greengrass.secretmanager;

import com.aws.iot.evergreen.testcommons.testutilities.EGExtension;
import com.aws.iot.greengrass.secretmanager.exception.SecretManagerException;
import com.aws.iot.greengrass.secretmanager.kernel.KernelClient;
import com.aws.iot.greengrass.secretmanager.model.AWSSecretResponse;
import com.aws.iot.greengrass.secretmanager.model.SecretDocument;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith({MockitoExtension.class, EGExtension.class})
class FileSecretDaoTest {
    private static final ObjectMapper JSON_OBJECT_MAPPER =
            new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
                    .registerModule(new JavaTimeModule());
    private final static String SECRET_NAME_1 = "secretA";
    private final static String SECRET_STRING_1 = "Its a secret!!";
    private final static String ARN_1 = "arn:aws:secretsmanager:us-east-1:9988977227:secret:snow-H9ySfh";
    private final static String VERSION_ID_1 = UUID.randomUUID().toString();
    private final static String LABEL1 = "new label1";
    private final static String LABEL2 = "new label2";
    private final static Instant DATE_1 = Instant.now();
    private final static String SECRET_NAME_2 = "secretB";
    private final static String SECRET_STRING_2 = "Its a secret!!, but another one";
    private final static String ARN_2 = "arn:aws:secretsmanager:us-east-1:9988977227:secret:newtake-H9ySfh";
    private final static String VERSION_ID_2 = UUID.randomUUID().toString();
    private final static String LABEL3 = "new label3";
    private final static String LABEL4 = "new label4";
    private final static Instant DATE_2 = Instant.now().minusSeconds(100L);

    private Path secretDir;
    private Path secretPath;

    @TempDir
    Path rootDir;

    @Mock
    KernelClient mockKernelClient;

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
    void cleanDir() throws IOException {
        when(mockKernelClient.getRoot()).thenReturn(rootDir);
        this.secretDir = rootDir.resolve(FileSecretDao.SECRETS_DIR);
        this.secretPath = secretDir.resolve(FileSecretDao.SECRET_FILE);
        Files.deleteIfExists(secretPath);
    }

    @Test
    void GIVEN_dao_store_WHEN_secrets_file_removed_THEN_store_get_save_fails() throws SecretManagerException, IOException {
        FileSecretDao dao = new FileSecretDao(mockKernelClient);
        List<AWSSecretResponse> response = getSecrets();
        SecretDocument doc = new SecretDocument(response);
        dao.saveAll(doc);
        assertTrue(Files.exists(secretPath));

        Files.deleteIfExists(secretPath);
        assertThrows(SecretManagerException.class, () -> dao.getAll());
    }

    @Test
    void GIVEN_dao_store_WHEN_secrets_saved_THEN_get_returns_them() throws SecretManagerException, IOException {
        FileSecretDao dao = new FileSecretDao(mockKernelClient);
        // Assert that secrets directory is created automatically on startup
        assertTrue(Files.exists(rootDir.resolve(FileSecretDao.SECRETS_DIR)));
        assertTrue(Files.isDirectory(rootDir.resolve(FileSecretDao.SECRETS_DIR)));
        assertFalse(Files.exists(secretPath));

        List<AWSSecretResponse> response = getSecrets();
        SecretDocument doc = new SecretDocument(response);
        dao.saveAll(doc);

        SecretDocument fileDocument = JSON_OBJECT_MAPPER.readValue(secretDir.resolve(FileSecretDao.SECRET_FILE).toFile(),
                new TypeReference<SecretDocument>(){});

        AWSSecretResponse firstSecretFromDisk = fileDocument.getSecrets().get(0);

        assertEquals(ARN_1, firstSecretFromDisk.getArn());
        assertEquals(SECRET_STRING_1, firstSecretFromDisk.getEncryptedSecretString());
        assertEquals(SECRET_NAME_1, firstSecretFromDisk.getName());
        assertEquals(VERSION_ID_1, firstSecretFromDisk.getVersionId());
        assertTrue(DATE_1.compareTo(firstSecretFromDisk.getCreatedDate()) == 0);
        assertThat(firstSecretFromDisk.getVersionStages(), hasItem(LABEL1));
        assertThat(firstSecretFromDisk.getVersionStages(), hasItem(LABEL2));

        AWSSecretResponse secondSecretFromDisk = fileDocument.getSecrets().get(1);

        assertEquals(ARN_2, secondSecretFromDisk.getArn());
        assertEquals(SECRET_STRING_2, secondSecretFromDisk.getEncryptedSecretString());
        assertEquals(SECRET_NAME_2, secondSecretFromDisk.getName());
        assertEquals(VERSION_ID_2, secondSecretFromDisk.getVersionId());
        assertTrue(DATE_2.compareTo(secondSecretFromDisk.getCreatedDate()) == 0);
        assertThat(secondSecretFromDisk.getVersionStages(), hasItem(LABEL3));
        assertThat(secondSecretFromDisk.getVersionStages(), hasItem(LABEL4));

        // Now read the structure from the dao object
        AWSSecretResponse firstSecretFromDao = dao.getAll().getSecrets().get(0);
        assertEquals(SECRET_NAME_1, firstSecretFromDao.getName());
        assertEquals(SECRET_STRING_1, firstSecretFromDao.getEncryptedSecretString());
        assertEquals(ARN_1, firstSecretFromDao.getArn());
        assertEquals(VERSION_ID_1, firstSecretFromDao.getVersionId());
        assertTrue(DATE_1.compareTo(firstSecretFromDao.getCreatedDate()) == 0);
        assertThat(firstSecretFromDao.getVersionStages(), hasItem(LABEL1));
        assertThat(firstSecretFromDao.getVersionStages(), hasItem(LABEL2));

        AWSSecretResponse secondSecretFromDao = dao.getAll().getSecrets().get(1);
        assertEquals(SECRET_NAME_2, secondSecretFromDao.getName());
        assertEquals(SECRET_STRING_2, secondSecretFromDao.getEncryptedSecretString());
        assertEquals(ARN_2, secondSecretFromDao.getArn());
        assertEquals(VERSION_ID_2, secondSecretFromDao.getVersionId());
        assertTrue(DATE_2.compareTo(secondSecretFromDao.getCreatedDate()) == 0);
        assertThat(secondSecretFromDao.getVersionStages(), hasItem(LABEL3));
        assertThat(secondSecretFromDao.getVersionStages(), hasItem(LABEL4));
    }
}