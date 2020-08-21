package com.aws.iot.greengrass.secretmanager;

import com.aws.iot.evergreen.testcommons.testutilities.EGExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(EGExtension.class)
class MemorySecretDaoTest {

    private final static String SECRET_NAME = "secretA";
    private final static String SECRET_STRING = "Its a secret!!";
    private final static String ARN = "arn:aws:secretsmanager:us-east-1:9988977227:secret:snow-H9ySfh";
    private final static String SECRET = "PlainTextSecret";
    private final static String VERSION_ID = UUID.randomUUID().toString();
    private final static String LABEL = "new label";
    private final static Instant DATE = Instant.now();


    private GetSecretValueResponse getDefaultSecretObject() {
        return GetSecretValueResponse.builder().secretString(SECRET_STRING)
                .name(SECRET_NAME)
                .arn(ARN)
                .createdDate(DATE)
                .versionId(VERSION_ID)
                .secretString(SECRET)
                .versionStages(new String[]{LABEL})
                .build();
    }

    @Test
    void GIVEN_dao_store_WHEN_object_saved_THEN_get_returns_it() {
        MemorySecretDao dao = new MemorySecretDao();
        dao.save("id1", getDefaultSecretObject());
        GetSecretValueResponse response = dao.get("id1").get();
        assertEquals(SECRET_NAME, response.name());
        assertEquals(SECRET, response.secretString());
        assertEquals(ARN, response.arn());
        assertEquals(VERSION_ID, response.versionId());
        assertTrue(DATE.compareTo(response.createdDate()) == 0);
        assertEquals(LABEL, response.versionStages().get(0));
    }

    @Test
    void GIVEN_dao_store_WHEN_multiple_objects_saved_THEN_get_all_returns_all() {
        MemorySecretDao dao = new MemorySecretDao();
        dao.save("id1", getDefaultSecretObject());
        dao.save("id2", getDefaultSecretObject());
        assertEquals(2, dao.getAll().size());
        assertEquals(SECRET_NAME, dao.getAll().get(0).name());
        assertEquals(SECRET_NAME, dao.getAll().get(1).name());

    }
}