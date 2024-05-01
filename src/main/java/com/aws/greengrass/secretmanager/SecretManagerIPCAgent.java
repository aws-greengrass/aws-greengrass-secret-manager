/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager;

import com.aws.greengrass.authorization.AuthorizationHandler;
import com.aws.greengrass.authorization.Permission;
import com.aws.greengrass.authorization.exceptions.AuthorizationException;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import com.aws.greengrass.secretmanager.exception.v1.GetSecretException;
import software.amazon.awssdk.aws.greengrass.GeneratedAbstractGetSecretValueOperationHandler;
import software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest;
import software.amazon.awssdk.aws.greengrass.model.GetSecretValueResponse;
import software.amazon.awssdk.aws.greengrass.model.ResourceNotFoundError;
import software.amazon.awssdk.aws.greengrass.model.ServiceError;
import software.amazon.awssdk.aws.greengrass.model.UnauthorizedError;
import software.amazon.awssdk.eventstreamrpc.OperationContinuationHandlerContext;
import software.amazon.awssdk.eventstreamrpc.model.EventStreamJsonMessage;

import javax.inject.Inject;

import static software.amazon.awssdk.aws.greengrass.GreengrassCoreIPCService.GET_SECRET_VALUE;

/**
 * Class to handle business logic for all SecretManager requests over IPC.
 */
public class SecretManagerIPCAgent {
    private static final Logger logger = LogManager.getLogger(SecretManagerIPCAgent.class);
    private final SecretManager secretManager;
    private final AuthorizationHandler authorizationHandler;

    /**
     * Constructor for secret manager ipc agent.
     *
     * @param secretManager        secret manager
     * @param authorizationHandler IPC authorization handler
     */
    @Inject
    public SecretManagerIPCAgent(SecretManager secretManager, AuthorizationHandler authorizationHandler) {
        this.secretManager = secretManager;
        this.authorizationHandler = authorizationHandler;
    }

    public GetSecretValueOperationHandler getSecretValueOperationHandler(OperationContinuationHandlerContext context) {
        return new GetSecretValueOperationHandler(context);
    }

    public void validateSecretIdAndDoAuthorization(String opCode, String serviceName, String secretId)
            throws AuthorizationException, GetSecretException {
        String arn = secretManager.validateSecretId(secretId);
        doAuthorization(opCode, serviceName, arn);
    }

    private void doAuthorization(String opCode, String serviceName, String secretId) throws AuthorizationException {
        authorizationHandler.isAuthorized(SecretManagerService.SECRET_MANAGER_SERVICE_NAME,
                Permission.builder().principal(serviceName).operation(opCode).resource(secretId).build());
    }

    class GetSecretValueOperationHandler extends GeneratedAbstractGetSecretValueOperationHandler {
        private final String serviceName;

        protected GetSecretValueOperationHandler(OperationContinuationHandlerContext context) {
            super(context);
            serviceName = context.getAuthenticationData().getIdentityLabel();
        }

        @Override
        protected void onStreamClosed() {

        }

        @Override
        public GetSecretValueResponse handleRequest(GetSecretValueRequest request) {
            logger.atDebug("ipc-get-secret-request").log();
            try {
                validateSecretIdAndDoAuthorization(GET_SECRET_VALUE, serviceName, request.getSecretId());
                logger.atInfo().event("secret-access").kv("Principal", serviceName).kv("secret", request.getSecretId())
                        .log("requested secret");
                return secretManager.getSecret(request);
            } catch (AuthorizationException e) {
                throw new UnauthorizedError(e.getMessage());
            } catch (GetSecretException e) {
                logger.atError().event("secret-access").kv("Principal", serviceName).kv("secret", request.getSecretId())
                        .setCause(e).log("Error happened with secret access");
                if (e.getStatus() == 404) {
                    ResourceNotFoundError rnf = new ResourceNotFoundError();
                    rnf.setMessage(e.getMessage());
                    rnf.setResourceType("secret");
                    throw rnf;
                }
                throw new ServiceError(e.getMessage());
            }
        }

        @Override
        public void handleStreamEvent(EventStreamJsonMessage streamRequestEvent) {

        }
    }
}
