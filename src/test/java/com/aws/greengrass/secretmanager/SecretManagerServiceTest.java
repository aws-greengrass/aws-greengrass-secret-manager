/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager;

import com.aws.greengrass.authorization.AuthorizationHandler;
import com.aws.greengrass.authorization.Permission;
import com.aws.greengrass.authorization.exceptions.AuthorizationException;
import com.aws.greengrass.dependency.State;
import com.aws.greengrass.ipc.ConnectionContext;
import com.aws.greengrass.ipc.common.FrameReader;
import com.aws.greengrass.ipc.services.common.ApplicationMessage;
import com.aws.greengrass.ipc.services.common.IPCUtil;
import com.aws.greengrass.ipc.services.secret.GetSecretValueResult;
import com.aws.greengrass.ipc.services.secret.SecretClientOpCodes;
import com.aws.greengrass.ipc.services.secret.SecretResponseStatus;
import com.aws.greengrass.lifecyclemanager.GreengrassService;
import com.aws.greengrass.lifecyclemanager.Kernel;
import com.aws.greengrass.secretmanager.exception.SecretManagerException;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static com.aws.greengrass.testcommons.testutilities.ExceptionLogProtector.ignoreExceptionOfType;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith({MockitoExtension.class, GGExtension.class})
public class SecretManagerServiceTest {
    private final String SECRET_ID = "secret";
    private final String VERSION_ID = "id";
    private final String VERSION_LABEL = "label";
    private final String CURRENT_LABEL = "AWSCURRENT";
    private Kernel kernel;

    @TempDir
    Path rootDir;

    @Mock
    ConnectionContext mockContext;

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
        kernel.parseArgs("-r", rootDir.toAbsolutePath().toString(), "-i", getClass().getResource(configFile).toString());
        kernel.getContext().addGlobalStateChangeListener((GreengrassService service, State was, State newState) -> {
            if (service.getName().equals(SecretManagerService.SECRET_MANAGER_SERVICE_NAME) && service.getState().equals(expectedState)) {
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

    private FrameReader.Message getInputMessage() throws IOException {
        com.aws.greengrass.ipc.services.secret.GetSecretValueRequest request =
                com.aws.greengrass.ipc.services.secret.GetSecretValueRequest.builder().secretId(SECRET_ID).build();
        ApplicationMessage msg = ApplicationMessage.builder().version(1)
                .opCode(SecretClientOpCodes.GET_SECRET.ordinal())
                .payload(IPCUtil.encode(request))
                .build();
        return new FrameReader.Message(msg.toByteArray());
    }

    private FrameReader.Message getInvalidInputMessage() throws IOException {
        ApplicationMessage msg = ApplicationMessage.builder().version(1)
                .opCode(SecretClientOpCodes.GET_SECRET.ordinal())
                .payload(IPCUtil.encode("Junk"))
                .build();
        return new FrameReader.Message(msg.toByteArray());
    }

    @Test
    void GIVEN_secret_service_WHEN_started_with_bad_parameter_config_THEN_starts_successfully(ExtensionContext context) throws InterruptedException {
        ignoreExceptionOfType(context, com.fasterxml.jackson.core.JsonParseException.class);
        startKernelWithConfig("badConfig.yaml", State.RUNNING);
    }

    @Test
    void GIVEN_secret_service_WHEN_load_secret_fails_THEN_service_errors(ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, SecretManagerException.class);

        doThrow(SecretManagerException.class).when(mockSecretManager).loadSecretsFromLocalStore();
        startKernelWithConfig("config.yaml", State.ERRORED);
    }

    @Test
    void GIVEN_secret_service_WHEN_started_without_secrets_THEN_starts_successfully(ExtensionContext context) throws InterruptedException {
        ignoreExceptionOfType(context, com.fasterxml.jackson.core.JsonParseException.class);
        startKernelWithConfig("emptyParameterConfig.yaml", State.RUNNING);
    }

    @Test
    void GIVEN_secret_service_WHEN_handler_called_THEN_correct_response_returned() throws Exception {
        startKernelWithConfig("config.yaml", State.RUNNING);
        final String secretValue = "secretValue";
        final String serviceName = "mockService";
        com.aws.greengrass.ipc.services.secret.GetSecretValueResult mockSecretResponse1 =
                com.aws.greengrass.ipc.services.secret.GetSecretValueResult.builder().secretString(secretValue)
                .secretId(SECRET_ID)
                .versionId(VERSION_ID)
                .versionStages(Arrays.asList(new String[]{CURRENT_LABEL, VERSION_LABEL}))
                .build();


        when(mockSecretManager.getSecret(any())).thenReturn(mockSecretResponse1);
        when(mockContext.getServiceName()).thenReturn("mockService");
        when(mockAuthorizationHandler.isAuthorized(stringCaptor.capture(), permissionCaptor.capture())).thenReturn(true);

        FrameReader.Message inputMessage = getInputMessage();
        Future<FrameReader.Message> fut = kernel.getContext().get(SecretManagerService.class).handleMessage(inputMessage, mockContext);
        FrameReader.Message m = fut.get();
        com.aws.greengrass.ipc.services.secret.GetSecretValueResult returnedResult =
                IPCUtil.decode(ApplicationMessage.fromBytes(m.getPayload()).getPayload(), GetSecretValueResult.class);
        assertEquals(SECRET_ID, returnedResult.getSecretId());
        assertEquals(VERSION_ID, returnedResult.getVersionId());
        assertThat(returnedResult.getVersionStages(), hasItem(CURRENT_LABEL));
        assertThat(returnedResult.getVersionStages(), hasItem(VERSION_LABEL));
        assertEquals(SecretResponseStatus.Success, returnedResult.getStatus());
        assertEquals(SecretManagerService.SECRET_MANAGER_SERVICE_NAME, stringCaptor.getValue());
        assertEquals(SecretManagerService.SECRETS_AUTHORIZATION_OPCODE, permissionCaptor.getValue().getOperation());
        assertEquals(serviceName, permissionCaptor.getValue().getPrincipal());
        assertEquals(SECRET_ID, permissionCaptor.getValue().getResource());
        verify(mockAuthorizationHandler, atLeastOnce()).registerComponent(SecretManagerService.SECRET_MANAGER_SERVICE_NAME,
                new HashSet<>(Arrays.asList(SecretManagerService.SECRETS_AUTHORIZATION_OPCODE)));
    }

    @Test
    void GIVEN_secret_service_WHEN_request_unauthorized_THEN_correct_response_returned(ExtensionContext context) throws Exception {
        startKernelWithConfig("config.yaml", State.RUNNING);
        ignoreExceptionOfType(context, AuthorizationException.class);
        when(mockContext.getServiceName()).thenReturn("mockService");
        when(mockAuthorizationHandler.isAuthorized(any(), any(Permission.class))).thenThrow(AuthorizationException.class);

        FrameReader.Message inputMessage = getInputMessage();
        Future<FrameReader.Message> fut = kernel.getContext().get(SecretManagerService.class).handleMessage(inputMessage, mockContext);
        FrameReader.Message m = fut.get();
        com.aws.greengrass.ipc.services.secret.GetSecretValueResult returnedResult =
                IPCUtil.decode(ApplicationMessage.fromBytes(m.getPayload()).getPayload(), GetSecretValueResult.class);
        assertNull(returnedResult.getSecretId());
        assertNull(returnedResult.getVersionId());
        assertNull(returnedResult.getVersionStages());
        assertEquals(SecretResponseStatus.Unauthorized, returnedResult.getStatus());
    }

    @Test
    void GIVEN_secret_service_WHEN_handler_call_errors_out_THEN_correct_response_returned(ExtensionContext context) throws Exception {
        startKernelWithConfig("config.yaml", State.RUNNING);
        ignoreExceptionOfType(context, com.fasterxml.jackson.databind.exc.MismatchedInputException.class);
        FrameReader.Message inputMessage = getInvalidInputMessage();
        Future<FrameReader.Message> fut = kernel.getContext().get(SecretManagerService.class).handleMessage(inputMessage, mockContext);
        FrameReader.Message m = fut.get();
        com.aws.greengrass.ipc.services.secret.GetSecretValueResult returnedResult =
                IPCUtil.decode(ApplicationMessage.fromBytes(m.getPayload()).getPayload(), GetSecretValueResult.class);
        assertEquals(SecretResponseStatus.InternalError, returnedResult.getStatus());
    }

}
