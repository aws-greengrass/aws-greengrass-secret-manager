package com.aws.iot.greengrass.secretmanager;

import com.aws.iot.evergreen.ipc.services.secret.GetSecretValueRequest;
import com.aws.iot.evergreen.ipc.services.secret.GetSecretValueResult;
import com.aws.iot.evergreen.ipc.services.secret.SecretResponseStatus;
import com.aws.iot.evergreen.testcommons.testutilities.EGExtension;
import com.aws.iot.greengrass.secretmanager.exception.SecretManagerException;
import com.aws.iot.greengrass.secretmanager.model.SecretConfiguration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static com.aws.iot.evergreen.testcommons.testutilities.ExceptionLogProtector.ignoreExceptionOfType;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith({MockitoExtension.class, EGExtension.class})
class SecretManagerTest {
    private static final String LATEST_LABEL = "AWSCURRENT";
    private static final String SECRET_NAME_1 = "Secret1";
    private static final String SECRET_NAME_2 = "Secret2";

    private static final String SECRET_VALUE_1 = "password";
    private static final String SECRET_VALUE_2 = "newPassword";
    private static final String SECRET_VERSION_1 = UUID.randomUUID().toString();
    private static final String SECRET_VERSION_2 = UUID.randomUUID().toString();
    private static final String SECRET_LABEL_1 = "Label1";
    private static final String SECRET_LABEL_2 = "Label2";
    private static final Instant SECRET_DATE_1 = Instant.now();
    private static final Instant SECRET_DATE_2 = Instant.now();

    private static final String ARN_1 = "arn:aws:secretsmanager:us-east-1:999936977227:secret:randomSecret-74lYJh";
    private static final String ARN_2 = "arn:aws:secretsmanager:us-east-1:111136977227:secret:shhhhh-32lYsd";

    @Mock
    private AWSSecretClient mockAWSSecretClient;

    @Mock
    private MemorySecretDao mockDao;

    private List<SecretConfiguration> getMockSecrets() {
        SecretConfiguration secret1 = SecretConfiguration.builder().arn("arn:aws:secretsmanager:us-east-1:999936977227:secret:randomSecret-74lYJh").build();
        SecretConfiguration secret2 = SecretConfiguration.builder().arn("arn:aws:secretsmanager:us-east-1:111136977227:secret:shhhhh-32lYsd").build();
        return new ArrayList() {{
            add(secret1);
            add(secret2);
        }};
    }

    @Test
    void GIVEN_secret_manager_WHEN_sync_from_cloud_THEN_secrets_are_loaded() throws Exception {
        GetSecretValueResponse result1 =
                GetSecretValueResponse.builder().name(SECRET_NAME_1)
                        .arn(ARN_1).createdDate(SECRET_DATE_1).secretString(SECRET_VALUE_1).versionId(SECRET_VERSION_1)
                        .versionStages(new String[]{LATEST_LABEL, SECRET_LABEL_1}).build();

        GetSecretValueResponse result2 =
                GetSecretValueResponse.builder().name(SECRET_NAME_2)
                        .arn(ARN_2).createdDate(SECRET_DATE_2).secretString(SECRET_VALUE_2).versionId(SECRET_VERSION_2)
                        .versionStages(new String[]{LATEST_LABEL, SECRET_LABEL_2}).build();

        List<GetSecretValueResponse> daoReturnList = new ArrayList<>();
        daoReturnList.add(result1);
        daoReturnList.add(result2);

        when(mockAWSSecretClient.getSecret(any())).thenReturn(result1).thenReturn(result2);
        when(mockDao.getAll()).thenReturn(daoReturnList);

        SecretManager sm = new SecretManager(mockAWSSecretClient, mockDao);
        sm.syncFromCloud(getMockSecrets());

        verify(mockDao, times(1)).save(ARN_1, result1);
        verify(mockDao, times(1)).save(ARN_2, result2);

        GetSecretValueRequest request = GetSecretValueRequest.builder().secretId(SECRET_NAME_1).build();
        GetSecretValueResult getSecretValueResult = sm.getSecret(request);

        assertEquals(SECRET_VALUE_1, getSecretValueResult.getSecretString());
        assertEquals(ARN_1, getSecretValueResult.getSecretId());
        assertEquals(SECRET_VERSION_1, getSecretValueResult.getVersionId());
        assertEquals(2, getSecretValueResult.getVersionStages().size());
        assertEquals(LATEST_LABEL, getSecretValueResult.getVersionStages().get(0));
        assertEquals(SECRET_LABEL_1, getSecretValueResult.getVersionStages().get(1));

        request = GetSecretValueRequest.builder().secretId(SECRET_NAME_2).build();
        getSecretValueResult = sm.getSecret(request);

        assertEquals(SECRET_VALUE_2, getSecretValueResult.getSecretString());
        assertEquals(ARN_2, getSecretValueResult.getSecretId());
        assertEquals(SECRET_VERSION_2, getSecretValueResult.getVersionId());
        assertEquals(2, getSecretValueResult.getVersionStages().size());
        assertEquals(LATEST_LABEL, getSecretValueResult.getVersionStages().get(0));
        assertEquals(SECRET_LABEL_2, getSecretValueResult.getVersionStages().get(1));

        // Make a request with a label
        request = GetSecretValueRequest.builder().secretId(SECRET_NAME_1).versionStage(SECRET_LABEL_1).build();
        getSecretValueResult = sm.getSecret(request);

        assertEquals(SECRET_VALUE_1, getSecretValueResult.getSecretString());
        assertEquals(ARN_1, getSecretValueResult.getSecretId());
        assertEquals(SECRET_VERSION_1, getSecretValueResult.getVersionId());
        assertEquals(2, getSecretValueResult.getVersionStages().size());
        assertEquals(LATEST_LABEL, getSecretValueResult.getVersionStages().get(0));
        assertEquals(SECRET_LABEL_1, getSecretValueResult.getVersionStages().get(1));

        request = GetSecretValueRequest.builder().secretId(SECRET_NAME_2).versionStage(SECRET_LABEL_2).build();
        getSecretValueResult = sm.getSecret(request);

        assertEquals(SECRET_VALUE_2, getSecretValueResult.getSecretString());
        assertEquals(ARN_2, getSecretValueResult.getSecretId());
        assertEquals(SECRET_VERSION_2, getSecretValueResult.getVersionId());
        assertEquals(2, getSecretValueResult.getVersionStages().size());
        assertEquals(LATEST_LABEL, getSecretValueResult.getVersionStages().get(0));
        assertEquals(SECRET_LABEL_2, getSecretValueResult.getVersionStages().get(1));

        // Make a request with version id now
        request = GetSecretValueRequest.builder().secretId(SECRET_NAME_1).versionId(SECRET_VERSION_1).build();
        getSecretValueResult = sm.getSecret(request);

        assertEquals(SECRET_VALUE_1, getSecretValueResult.getSecretString());
        assertEquals(ARN_1, getSecretValueResult.getSecretId());
        assertEquals(SECRET_VERSION_1, getSecretValueResult.getVersionId());
        assertEquals(2, getSecretValueResult.getVersionStages().size());
        assertEquals(LATEST_LABEL, getSecretValueResult.getVersionStages().get(0));
        assertEquals(SECRET_LABEL_1, getSecretValueResult.getVersionStages().get(1));

        request = GetSecretValueRequest.builder().secretId(SECRET_NAME_2).versionId(SECRET_VERSION_2).build();
        getSecretValueResult = sm.getSecret(request);

        assertEquals(SECRET_VALUE_2, getSecretValueResult.getSecretString());
        assertEquals(ARN_2, getSecretValueResult.getSecretId());
        assertEquals(SECRET_VERSION_2, getSecretValueResult.getVersionId());
        assertEquals(2, getSecretValueResult.getVersionStages().size());
        assertEquals(LATEST_LABEL, getSecretValueResult.getVersionStages().get(0));
        assertEquals(SECRET_LABEL_2, getSecretValueResult.getVersionStages().get(1));
    }

    @Test
    void GIVEN_secret_manager_WHEN_cloud_errors_THEN_secrets_are_not_loaded(ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, SecretManagerException.class);
        when(mockAWSSecretClient.getSecret(any())).thenThrow(SecretManagerException.class);
        SecretManager sm = new SecretManager(mockAWSSecretClient, mockDao);
        sm.syncFromCloud(getMockSecrets());
        verify(mockDao, never()).save(any(), any());
    }

    @Test
    void GIVEN_secret_manager_WHEN_get_called_with_invalid_request_THEN_proper_errors_are_returned() throws Exception {
        SecretManager sm = new SecretManager(mockAWSSecretClient, mockDao);
        GetSecretValueRequest request = GetSecretValueRequest.builder().build();
        GetSecretValueResult response = sm.getSecret(request);
        assertEquals(SecretResponseStatus.InvalidRequest, response.getStatus());
        assertEquals("SecretId absent in the request", response.getErrorMessage());

        // Create a request for secret which is not present
        request = GetSecretValueRequest.builder().secretId(SECRET_NAME_1).build();
        response = sm.getSecret(request);
        assertEquals(SecretResponseStatus.InvalidRequest, response.getStatus());
        assertEquals("Secret not found " + SECRET_NAME_1, response.getErrorMessage());

        // Create a request for secret arn which is not present
        request = GetSecretValueRequest.builder().secretId(ARN_1).build();
        response = sm.getSecret(request);
        assertEquals(SecretResponseStatus.InvalidRequest, response.getStatus());
        assertEquals("Secret not found " + ARN_1, response.getErrorMessage());

        // Now add 2 secrets to the store
        GetSecretValueResponse result1 =
                GetSecretValueResponse.builder().name(SECRET_NAME_1)
                        .arn(ARN_1).createdDate(SECRET_DATE_1).secretString(SECRET_VALUE_1).versionId(SECRET_VERSION_1)
                        .versionStages(new String[]{LATEST_LABEL, SECRET_LABEL_1}).build();

        GetSecretValueResponse result2 =
                GetSecretValueResponse.builder().name(SECRET_NAME_2)
                        .arn(ARN_2).createdDate(SECRET_DATE_2).secretString(SECRET_VALUE_2).versionId(SECRET_VERSION_2)
                        .versionStages(new String[]{LATEST_LABEL, SECRET_LABEL_2}).build();

        List<GetSecretValueResponse> daoReturnList = new ArrayList<>();
        daoReturnList.add(result1);
        daoReturnList.add(result2);
        when(mockDao.getAll()).thenReturn(daoReturnList);
        // Actually load the secrets
        sm.loadSecretsFromLocalStore();

        // Create a request for secret with both version and label
        request = GetSecretValueRequest.builder()
                .secretId(SECRET_NAME_1)
                .versionId(SECRET_VERSION_1)
                .versionStage(SECRET_LABEL_1)
                .build();
        response = sm.getSecret(request);
        assertEquals(SecretResponseStatus.InvalidRequest, response.getStatus());
        assertEquals("Both versionId and Stage are set in the request", response.getErrorMessage());


        // Create a request for secret with an invalid version
        String invalidVersion = "InvalidVersion";
        request = GetSecretValueRequest.builder()
                .secretId(SECRET_NAME_1)
                .versionId(invalidVersion)
                .build();
        response = sm.getSecret(request);
        assertEquals(SecretResponseStatus.InvalidRequest, response.getStatus());
        assertEquals("Version Id " + invalidVersion + " not found for secret " + SECRET_NAME_1, response.getErrorMessage());

        // Create a request for secret with an invalid label
        String invalidLabel = "InvalidLabel";
        request = GetSecretValueRequest.builder()
                .secretId(SECRET_NAME_1)
                .versionStage(invalidLabel)
                .build();
        response = sm.getSecret(request);
        assertEquals(SecretResponseStatus.InvalidRequest, response.getStatus());
        assertEquals("Version stage " + invalidLabel + " not found for secret " + SECRET_NAME_1, response.getErrorMessage());
    }
}
