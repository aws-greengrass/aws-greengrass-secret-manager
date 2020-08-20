package com.aws.iot.greengrass.secretmanager;

import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MemorySecretDaoTest {

    private final static String SECRET_NAME = "secretA";
    private final static String SECRET_STRING = "Its a secret!!";
    private final static String ARN = "arn:aws:secretsmanager:us-east-1:9988977227:secret:snow-H9ySfh";
    private final static String SECRET = "PlainTextSecret";
    private final static String VERSION_ID = UUID.randomUUID().toString();
    private final static String LABEL = "new label";
    private final static Date DATE = new Date();


    private GetSecretValueResult getDefaultSecretObject() {
        return new GetSecretValueResult().withSecretString(SECRET_STRING)
                .withName(SECRET_NAME)
                .withARN(ARN)
                .withCreatedDate(DATE)
                .withVersionId(VERSION_ID)
                .withSecretString(SECRET)
                .withVersionStages(Arrays.asList(new String[]{LABEL}));
    }

    @Test
    void GIVEN_dao_store_WHEN_object_saved_THEN_get_returns_it() {
        MemorySecretDao dao = new MemorySecretDao();
        dao.save("id1", getDefaultSecretObject());
        GetSecretValueResult result = dao.get("id1").get();
        assertEquals(SECRET_NAME, result.getName());
        assertEquals(SECRET, result.getSecretString());
        assertEquals(ARN, result.getARN());
        assertEquals(VERSION_ID, result.getVersionId());
        assertTrue(DATE.compareTo(result.getCreatedDate()) == 0);
        assertEquals(LABEL, result.getVersionStages().get(0));
    }

    @Test
    void GIVEN_dao_store_WHEN_multiple_objects_saved_THEN_get_all_returns_all() {
        MemorySecretDao dao = new MemorySecretDao();
        dao.save("id1", getDefaultSecretObject());
        dao.save("id2", getDefaultSecretObject());
        assertEquals(2, dao.getAll().size());
        assertEquals(SECRET_NAME, dao.getAll().get(0).getName());
        assertEquals(SECRET_NAME, dao.getAll().get(1).getName());

    }
}