package com.aws.iot.greengrass.secretmanager;

import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import com.aws.iot.greengrass.secretmanager.exception.SecretManagerException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith({MockitoExtension.class})
class AWSClientTest {

    private static final String SECRET_NAME = "EGUnitTest1";
    private static final String SECRET_VALUE = "plainText";
    private static final String LATEST_LABEL = "AWSCURRENT";

    @Mock
    AWSSecretsManager mockAwsClient;

    @Test
    void getSecret() throws SecretManagerException {
        GetSecretValueResult mockResult = new GetSecretValueResult().withSecretString(SECRET_VALUE).withName(SECRET_NAME);
        when(mockAwsClient.getSecretValue(any())).thenReturn(mockResult);
        AWSClient cloud = new AWSClient(mockAwsClient);
        GetSecretValueRequest request = new GetSecretValueRequest().withSecretId(SECRET_NAME).withVersionStage(LATEST_LABEL);
        GetSecretValueResult result = cloud.getSecret(request);
        assertEquals(SECRET_NAME, result.getName());
        assertEquals(SECRET_VALUE, result.getSecretString());
    }
}