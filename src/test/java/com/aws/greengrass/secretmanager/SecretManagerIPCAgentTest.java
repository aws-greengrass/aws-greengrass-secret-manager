/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager;

import com.aws.greengrass.testcommons.testutilities.GGExtension;
import software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest;
import software.amazon.awssdk.aws.greengrass.model.GetSecretValueResponse;
import software.amazon.awssdk.aws.greengrass.model.SecretValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.crt.eventstream.ServerConnectionContinuation;
import software.amazon.awssdk.eventstreamrpc.AuthenticationData;
import software.amazon.awssdk.eventstreamrpc.OperationContinuationHandlerContext;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith({MockitoExtension.class, GGExtension.class})
public class SecretManagerIPCAgentTest {
    private static final String TEST_SERVICE = "TestService";
    private final String SECRET_ID = "secret";
    private final String VERSION_ID = "id";
    @Mock
    OperationContinuationHandlerContext mockContext;

    @Mock
    SecretManagerService mockSecretManagerService;

    @Mock
    AuthenticationData mockAuthenticationData;

    @Captor
    ArgumentCaptor<GetSecretValueRequest> getSecretValueRequestArgumentCaptor;
    @Captor
    ArgumentCaptor<String> stringArgumentCaptor;

    private SecretManagerIPCAgent secretManagerIPCAgent;

    @BeforeEach
    void setup() {
        when(mockContext.getContinuation()).thenReturn(mock(ServerConnectionContinuation.class));
        when(mockContext.getAuthenticationData()).thenReturn(mockAuthenticationData);
        when(mockAuthenticationData.getIdentityLabel()).thenReturn(TEST_SERVICE);
        this.secretManagerIPCAgent = new SecretManagerIPCAgent();
        secretManagerIPCAgent.setSecretManagerService(mockSecretManagerService);
    }

    @Test
    void GIVEN_SecretManagerIPCAgent_WHEN_handle_request_THEN_get_secret() {
        GetSecretValueRequest request = new GetSecretValueRequest();
        request.setSecretId(SECRET_ID);
        request.setVersionId(VERSION_ID);

        String secretString = "secretValue";
        SecretValue secretValue = new SecretValue();
        secretValue.setSecretString(secretString);
        GetSecretValueResponse expectedResponse = new GetSecretValueResponse();
        expectedResponse.setSecretId(SECRET_ID);
        expectedResponse.setSecretValue(secretValue);
        expectedResponse.setVersionId(VERSION_ID);

        when(mockSecretManagerService.handleIPCRequest(any(), any())).thenReturn(expectedResponse);
        GetSecretValueResponse actualResponse =
                secretManagerIPCAgent.getSecretValueOperationHandler(mockContext).handleRequest(request);
        verify(mockSecretManagerService).handleIPCRequest(getSecretValueRequestArgumentCaptor.capture(),
                stringArgumentCaptor.capture());
        assertEquals(TEST_SERVICE, stringArgumentCaptor.getValue());
        assertEquals(request, getSecretValueRequestArgumentCaptor.getValue());
        assertEquals(expectedResponse, actualResponse);
    }
}
