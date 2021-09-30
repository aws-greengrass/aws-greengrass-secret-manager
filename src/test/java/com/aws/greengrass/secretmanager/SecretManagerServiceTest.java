/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager;

import com.aws.greengrass.authorization.AuthorizationHandler;
import com.aws.greengrass.authorization.Permission;
import com.aws.greengrass.authorization.exceptions.AuthorizationException;
import com.aws.greengrass.dependency.State;
import com.aws.greengrass.lifecyclemanager.GreengrassService;
import com.aws.greengrass.lifecyclemanager.Kernel;
import com.aws.greengrass.secretmanager.exception.SecretCryptoException;
import com.aws.greengrass.secretmanager.exception.SecretManagerException;
import com.aws.greengrass.secretmanager.exception.v1.GetSecretException;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.aws.greengrass.model.GetSecretValueResponse;
import software.amazon.awssdk.aws.greengrass.model.ResourceNotFoundError;
import software.amazon.awssdk.aws.greengrass.model.SecretValue;
import software.amazon.awssdk.aws.greengrass.model.ServiceError;
import software.amazon.awssdk.aws.greengrass.model.UnauthorizedError;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static com.aws.greengrass.secretmanager.TestUtil.ignoreErrors;
import static com.aws.greengrass.testcommons.testutilities.ExceptionLogProtector.ignoreExceptionOfType;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static software.amazon.awssdk.aws.greengrass.GreengrassCoreIPCServiceModel.GET_SECRET_VALUE;

@ExtendWith({MockitoExtension.class, GGExtension.class})
public class SecretManagerServiceTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private final String SECRET_ID = "secret";
    private final String SECRET_NAME = "secretName";
    private final String VERSION_ID = "id";
    private final String VERSION_LABEL = "label";
    private final String CURRENT_LABEL = "AWSCURRENT";
    private Kernel kernel;

    @TempDir
    Path rootDir;

    @Mock
    SecretManager mockSecretManager;

    @Mock
    AuthorizationHandler mockAuthorizationHandler;

    @Captor
    ArgumentCaptor<String> stringCaptor;

    @Captor
    ArgumentCaptor<Permission> permissionCaptor;

    void startKernelWithConfig(String configFile, State expectedState) throws InterruptedException {
        CountDownLatch secretManagerRunning = new CountDownLatch(1);
        kernel = new Kernel();
        kernel.parseArgs("-r", rootDir.toAbsolutePath().toString(), "-i",
                getClass().getResource(configFile).toString());
        kernel.getContext().addGlobalStateChangeListener((GreengrassService service, State was, State newState) -> {
            if (service.getName().equals(SecretManagerService.SECRET_MANAGER_SERVICE_NAME) && service.getState()
                    .equals(expectedState)) {
                secretManagerRunning.countDown();
            }
        });
        kernel.getContext().put(SecretManager.class, mockSecretManager);
        kernel.getContext().put(AuthorizationHandler.class, mockAuthorizationHandler);
        kernel.launch();
        assertTrue(secretManagerRunning.await(10, TimeUnit.SECONDS));
    }

    @AfterEach
    void cleanup() {
        kernel.shutdown();
    }

    @BeforeEach
    void setup(ExtensionContext context) {
        ignoreErrors(context);
    }

    @Test
    void GIVEN_secret_service_WHEN_started_with_bad_parameter_config_THEN_starts_successfully(ExtensionContext context)
            throws InterruptedException {
        ignoreExceptionOfType(context, java.lang.IllegalArgumentException.class);
        startKernelWithConfig("badConfig.yaml", State.RUNNING);
    }

    @Test
    void GIVEN_secret_service_WHEN_load_secret_fails_THEN_service_errors(ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, SecretManagerException.class);

        doThrow(SecretManagerException.class).when(mockSecretManager).loadSecretsFromLocalStore();
        startKernelWithConfig("config.yaml", State.ERRORED);
    }

    @Test
    void GIVEN_secret_service_WHEN_load_secret_fails_with_crypto_error_THEN_service_reloads_secrets(ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, SecretManagerException.class);

        SecretManagerException ex = new SecretManagerException(new SecretCryptoException("Bad"));
        doThrow(ex).when(mockSecretManager).loadSecretsFromLocalStore();
        startKernelWithConfig("config.yaml", State.RUNNING);
        verify(mockSecretManager).syncFromCloud(any());
    }

    @Test
    void GIVEN_secret_service_WHEN_started_without_secrets_THEN_starts_successfully(ExtensionContext context)
            throws InterruptedException {
        startKernelWithConfig("emptyParameterConfig.yaml", State.RUNNING);
    }

    @Test
    void GIVEN_secret_service_WHEN_started_without_secret_entry_THEN_starts_successfully(ExtensionContext context)
            throws InterruptedException {
        startKernelWithConfig("emptySecretConfig.yaml", State.RUNNING);
    }

    private com.aws.greengrass.secretmanager.model.v1.GetSecretValueResult convertSecret(byte[] bytes)
            throws IOException {
        return OBJECT_MAPPER.readValue(bytes, com.aws.greengrass.secretmanager.model.v1.GetSecretValueResult.class);
    }

    @Test
    void GIVEN_secret_service_WHEN_v1_get_called_THEN_correct_response_returned() throws Exception {
        startKernelWithConfig("config.yaml", State.RUNNING);
        final String secretValue = "secretValue";
        final String serviceName = "mockService";
        final Date currentTime = Date.from(Instant.now());
        com.aws.greengrass.secretmanager.model.v1.GetSecretValueResult expectedResponse =
                com.aws.greengrass.secretmanager.model.v1.GetSecretValueResult.builder().secretString(secretValue)
                        .arn(SECRET_ID).name(SECRET_NAME).versionId(VERSION_ID)
                        .versionStages(Arrays.asList(new String[]{CURRENT_LABEL, VERSION_LABEL}))
                        .createdDate(currentTime).build();

        when(mockSecretManager.getSecret(any(com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest.class)))
                .thenReturn(expectedResponse);
        when(mockSecretManager.validateSecretId(SECRET_ID)).thenReturn(SECRET_ID);
        when(mockAuthorizationHandler.isAuthorized(stringCaptor.capture(), permissionCaptor.capture()))
                .thenReturn(true);

        String requestString = String.format("{\"SecretId\": \"%s\", \"VersionId\": \"%s\"}", SECRET_ID, VERSION_ID);
        byte[] getSecretResponse =
                kernel.getContext().get(SecretManagerService.class).getSecret(serviceName, requestString.getBytes());

        com.aws.greengrass.secretmanager.model.v1.GetSecretValueResult actualResponse =
                convertSecret(getSecretResponse);

        assertEquals(SECRET_ID, actualResponse.getArn());
        assertEquals(SECRET_NAME, actualResponse.getName());
        assertEquals(VERSION_ID, actualResponse.getVersionId());
        assertEquals(secretValue, actualResponse.getSecretString());
        assertThat(actualResponse.getVersionStages(), hasItem(CURRENT_LABEL));
        assertThat(actualResponse.getVersionStages(), hasItem(VERSION_LABEL));
        assertEquals(currentTime, actualResponse.getCreatedDate());
        assertEquals(SecretManagerService.SECRET_MANAGER_SERVICE_NAME, stringCaptor.getValue());
        assertEquals(GET_SECRET_VALUE, permissionCaptor.getValue().getOperation());
        assertEquals(serviceName, permissionCaptor.getValue().getPrincipal());
        assertEquals(SECRET_ID, permissionCaptor.getValue().getResource());
        verify(mockAuthorizationHandler, atLeastOnce())
                .registerComponent(SecretManagerService.SECRET_MANAGER_SERVICE_NAME,
                        new HashSet<>(Arrays.asList(GET_SECRET_VALUE)));

        // Now request with secret name that maps to the arn
        when(mockSecretManager.validateSecretId(SECRET_NAME)).thenReturn(SECRET_ID);
        String newRequestString =
                String.format("{\"SecretId\": \"%s\", \"VersionId\": \"%s\"}", SECRET_NAME, VERSION_ID);

        getSecretResponse =
                kernel.getContext().get(SecretManagerService.class).getSecret(serviceName, newRequestString.getBytes());

        com.aws.greengrass.secretmanager.model.v1.GetSecretValueResult newActualResponse =
                convertSecret(getSecretResponse);
        assertEquals(actualResponse, newActualResponse);
    }

    private com.aws.greengrass.secretmanager.model.v1.GetSecretValueError convertError(byte[] bytes)
            throws IOException {
        return OBJECT_MAPPER.readValue(bytes, com.aws.greengrass.secretmanager.model.v1.GetSecretValueError.class);
    }
    @Test
    void GIVEN_secret_service_WHEN_v1_get_called_and_errors_THEN_correct_response_returned(ExtensionContext context)
            throws Exception {
        ignoreExceptionOfType(context, RuntimeException.class);
        startKernelWithConfig("config.yaml", State.RUNNING);
        final String serviceName = "mockService";

        when(mockSecretManager.getSecret(any(com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest.class)))
                .thenThrow(new GetSecretException(400, "getSecret Error"));
        when(mockAuthorizationHandler.isAuthorized(any(), any())).thenReturn(true);

        com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest request =
                com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest.builder().secretId(SECRET_ID)
                        .versionId(VERSION_ID).build();
        byte[] byteRequest = OBJECT_MAPPER.writeValueAsBytes(request);
        byte[] getSecretResponse = kernel.getContext().get(SecretManagerService.class).getSecret(serviceName,
                byteRequest);

        com.aws.greengrass.secretmanager.model.v1.GetSecretValueError parsedResponse = convertError(getSecretResponse);
        assertEquals(400, parsedResponse.getStatus());
        assertEquals("getSecret Error", parsedResponse.getMessage());

        // Now passing bogus request
        getSecretResponse =
                kernel.getContext().get(SecretManagerService.class).getSecret(serviceName, "Hello".getBytes());

        parsedResponse = convertError(getSecretResponse);

        assertEquals(400, parsedResponse.getStatus());
        assertEquals("Unable to parse request", parsedResponse.getMessage());

        // now let the auth fail
        when(mockAuthorizationHandler.isAuthorized(any(), any())).
                thenThrow(new AuthorizationException("Auth error"));
        getSecretResponse = kernel.getContext().get(SecretManagerService.class).getSecret(serviceName, byteRequest);
        parsedResponse = convertError(getSecretResponse);

        assertEquals(403, parsedResponse.getStatus());
        assertEquals("Auth error", parsedResponse.getMessage());

        //Case for generic errors
        reset(mockAuthorizationHandler);
        when(mockAuthorizationHandler.isAuthorized(any(), any())).thenReturn(true);
        when(mockSecretManager.getSecret(any(com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest.class)))
                .thenThrow(new RuntimeException("Generic Error"));
        getSecretResponse = kernel.getContext().get(SecretManagerService.class).getSecret(serviceName, byteRequest);
        parsedResponse = convertError(getSecretResponse);

        assertEquals(500, parsedResponse.getStatus());
        assertEquals("Generic Error", parsedResponse.getMessage());

        // Now invalid secretId
        when(mockSecretManager.validateSecretId(SECRET_ID)).thenThrow(new GetSecretException(400, "getSecret Error"));
        getSecretResponse = kernel.getContext().get(SecretManagerService.class).getSecret(serviceName, byteRequest);
        parsedResponse = convertError(getSecretResponse);

        assertEquals(400, parsedResponse.getStatus());
        assertEquals("getSecret Error", parsedResponse.getMessage());
    }

    @Test
    void GIVEN_secret_service_WHEN_v1_get_called_THEN_correct_errors_returned(ExtensionContext context)
            throws Exception {
        ignoreExceptionOfType(context, AuthorizationException.class);
        startKernelWithConfig("config.yaml", State.RUNNING);
        final String serviceName = "mockService";

        when(mockAuthorizationHandler.isAuthorized(any(), any())).thenThrow(AuthorizationException.class);
        com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest request =
                com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest.builder().secretId(SECRET_ID)
                        .versionId(VERSION_ID).build();
        byte[] byteRequest = OBJECT_MAPPER.writeValueAsBytes(request);
        byte[] getSecretResponse = kernel.getContext().get(SecretManagerService.class).getSecret(serviceName,
                byteRequest);
        com.aws.greengrass.secretmanager.model.v1.GetSecretValueError actualResponse =
                convertError(getSecretResponse);

        assertEquals(403, actualResponse.getStatus());

        // simulate get secret throwing exception internally
        reset(mockAuthorizationHandler);
        when(mockAuthorizationHandler.isAuthorized(any(), any())).thenReturn(true);
        GetSecretException exception = new GetSecretException(400, "test");
        when(mockSecretManager.getSecret(any(com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest.class)))
                .thenThrow(exception);
        getSecretResponse = kernel.getContext().get(SecretManagerService.class).getSecret(serviceName, byteRequest);

        actualResponse = convertError(getSecretResponse);
        assertEquals(400, actualResponse.getStatus());
        assertThat(actualResponse.getMessage(), containsString("test"));

        // Now send in a bad request
        byteRequest = OBJECT_MAPPER.writeValueAsBytes("bad request");
        getSecretResponse = kernel.getContext().get(SecretManagerService.class).getSecret(serviceName, byteRequest);
        actualResponse = convertError(getSecretResponse);
        assertEquals(400, actualResponse.getStatus());
        assertThat(actualResponse.getMessage(), containsString("Unable to parse request"));
    }


    @Test
    void GIVEN_secret_service_WHEN_request_invalid_THEN_correct_response_returned(ExtensionContext context)
            throws Exception {
        ignoreExceptionOfType(context, GetSecretException.class);
        startKernelWithConfig("config.yaml", State.RUNNING);
        final String serviceName = "mockService";
        when(mockSecretManager.validateSecretId(SECRET_ID)).thenThrow(GetSecretException.class);

        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest request =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        request.setSecretId(SECRET_ID);
        request.setVersionId(VERSION_ID);

        assertThrows(ServiceError.class,
                () -> kernel.getContext().get(SecretManagerService.class).getSecretIPC(request, serviceName));
    }


    @Test
    void GIVEN_secret_service_WHEN_ipc_handler_called_THEN_correct_response_returned() throws Exception {
        startKernelWithConfig("config.yaml", State.RUNNING);
        final String secretString = "secretValue";
        final String serviceName = "mockService";
        GetSecretValueResponse response = new GetSecretValueResponse();
        SecretValue secretValue = new SecretValue();
        secretValue.setSecretString(secretString);
        response.setSecretValue(secretValue);
        response.setSecretId(SECRET_ID);
        response.setVersionId(VERSION_ID);
        response.setVersionStage(Arrays.asList(CURRENT_LABEL, VERSION_LABEL));
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest request =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        request.setSecretId(SECRET_ID);
        request.setVersionId(VERSION_ID);

        when(mockSecretManager.validateSecretId(SECRET_ID)).thenReturn(SECRET_ID);
        when(mockSecretManager.getSecret(any(software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest.class)))
                .thenReturn(response);
        when(mockAuthorizationHandler.isAuthorized(stringCaptor.capture(), permissionCaptor.capture()))
                .thenReturn(true);

        GetSecretValueResponse returnedResponse =
                kernel.getContext().get(SecretManagerService.class).getSecretIPC(request, serviceName);
        assertEquals(response, returnedResponse);
        assertEquals(SecretManagerService.SECRET_MANAGER_SERVICE_NAME, stringCaptor.getValue());
        assertEquals(GET_SECRET_VALUE, permissionCaptor.getValue().getOperation());
        assertEquals(serviceName, permissionCaptor.getValue().getPrincipal());
        assertEquals(SECRET_ID, permissionCaptor.getValue().getResource());
        verify(mockAuthorizationHandler, atLeastOnce())
                .registerComponent(SecretManagerService.SECRET_MANAGER_SERVICE_NAME,
                        new HashSet<>(Arrays.asList(GET_SECRET_VALUE)));
    }

    @Test
    void GIVEN_secret_service_WHEN_ipc_request_unauthorized_THEN_throws_unauthorized_exception() throws Exception {
        startKernelWithConfig("config.yaml", State.RUNNING);
        final String serviceName = "mockService";
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest request =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        request.setSecretId(SECRET_ID);
        request.setVersionId(VERSION_ID);
        when(mockAuthorizationHandler.isAuthorized(any(), any(Permission.class)))
                .thenThrow(AuthorizationException.class);

        assertThrows(UnauthorizedError.class,
                () -> kernel.getContext().get(SecretManagerService.class).getSecretIPC(request, serviceName));
    }

    @Test
    void GIVEN_secret_service_WHEN_ipc_request_get_secret_errors_THEN_throw_error(ExtensionContext context)
            throws Exception {
        ignoreExceptionOfType(context, GetSecretException.class);
        startKernelWithConfig("config.yaml", State.RUNNING);
        final String serviceName = "mockService";
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest request =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        request.setSecretId(SECRET_ID);
        request.setVersionId(VERSION_ID);

        when(mockSecretManager.getSecret(any(software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest.class)))
                .thenThrow(new GetSecretException(400, "getSecret Error"));
        assertThrows(ServiceError.class,
                () -> kernel.getContext().get(SecretManagerService.class).getSecretIPC(request, serviceName));

        when(mockSecretManager.getSecret(any(software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest.class)))
                .thenThrow(new GetSecretException(404, "secretNotFoundErr"));
        assertThrows(ResourceNotFoundError.class,
                () -> kernel.getContext().get(SecretManagerService.class).getSecretIPC(request, serviceName));
    }

}
