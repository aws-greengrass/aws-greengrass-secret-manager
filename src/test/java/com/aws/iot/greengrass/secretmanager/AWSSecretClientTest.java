package com.aws.iot.greengrass.secretmanager;

import com.aws.iot.evergreen.testcommons.testutilities.EGExtension;
import com.aws.iot.greengrass.secretmanager.exception.SecretManagerException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.DecryptionFailureException;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.InternalServiceErrorException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidParameterException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidRequestException;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith({MockitoExtension.class, EGExtension.class})
class AWSSecretClientTest {

    private static final String SECRET_NAME = "EGUnitTest1";
    private static final String SECRET_VALUE = "plainText";
    private static final String LATEST_LABEL = "AWSCURRENT";

    @Mock
    SecretsManagerClient mockAwsClient;

    @Test
    void GIVEN_aws_client_WHEN_get_secret_THEN_secret_returned() throws SecretManagerException {
        GetSecretValueResponse mockResult = GetSecretValueResponse.builder().secretString(SECRET_VALUE).name(SECRET_NAME).build();
        when(mockAwsClient.getSecretValue(any(GetSecretValueRequest.class))).thenReturn(mockResult);
        AWSSecretClient cloud = new AWSSecretClient(mockAwsClient);
        GetSecretValueRequest request = GetSecretValueRequest.builder().secretId(SECRET_NAME).versionStage(LATEST_LABEL).build();
        GetSecretValueResponse result = cloud.getSecret(request);
        assertEquals(SECRET_NAME, result.name());
        assertEquals(SECRET_VALUE, result.secretString());
    }

    @Test
    void GIVEN_aws_client_throws_WHEN_get_secret_THEN_valid_exception_returned() throws SecretManagerException {
        when(mockAwsClient.getSecretValue(any(GetSecretValueRequest.class))).thenThrow(InternalServiceErrorException.class);
        AWSSecretClient cloud = new AWSSecretClient(mockAwsClient);
        GetSecretValueRequest request = GetSecretValueRequest.builder().secretId(SECRET_NAME).versionStage(LATEST_LABEL).build();
        assertThrows(SecretManagerException.class, () -> cloud.getSecret(request));

        when(mockAwsClient.getSecretValue(any(GetSecretValueRequest.class))).thenThrow(DecryptionFailureException.class);
        assertThrows(SecretManagerException.class, () -> cloud.getSecret(request));

        when(mockAwsClient.getSecretValue(any(GetSecretValueRequest.class))).thenThrow(ResourceNotFoundException.class);
        assertThrows(SecretManagerException.class, () -> cloud.getSecret(request));

        when(mockAwsClient.getSecretValue(any(GetSecretValueRequest.class))).thenThrow(InvalidParameterException.class);
        assertThrows(SecretManagerException.class, () -> cloud.getSecret(request));

        when(mockAwsClient.getSecretValue(any(GetSecretValueRequest.class))).thenThrow(InvalidRequestException.class);
        assertThrows(SecretManagerException.class, () -> cloud.getSecret(request));
    }

    @Test
    void GIVEN_aws_client_throws_WHEN_get_invalid_secret_THEN_valid_exception_returned() throws SecretManagerException {
        AWSSecretClient cloud = new AWSSecretClient(mockAwsClient);
        // empty secret
        GetSecretValueRequest emptyRequest = GetSecretValueRequest.builder().versionStage(LATEST_LABEL).build();
        assertThrows(IllegalArgumentException.class, () -> cloud.getSecret(emptyRequest));

        // empty secret
        GetSecretValueRequest emptyVersionAndLabel = GetSecretValueRequest.builder().secretId(SECRET_NAME).build();
        assertThrows(IllegalArgumentException.class, () -> cloud.getSecret(emptyVersionAndLabel));

    }
}
