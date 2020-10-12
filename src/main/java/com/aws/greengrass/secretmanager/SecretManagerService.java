/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager;

import com.aws.greengrass.authorization.AuthorizationHandler;
import com.aws.greengrass.authorization.Permission;
import com.aws.greengrass.authorization.exceptions.AuthorizationException;
import com.aws.greengrass.config.Topic;
import com.aws.greengrass.config.Topics;
import com.aws.greengrass.config.WhatHappened;
import com.aws.greengrass.dependency.ImplementsService;
import com.aws.greengrass.dependency.State;
import com.aws.greengrass.ipc.ConnectionContext;
import com.aws.greengrass.ipc.IPCRouter;
import com.aws.greengrass.ipc.common.BuiltInServiceDestinationCode;
import com.aws.greengrass.ipc.common.FrameReader;
import com.aws.greengrass.ipc.exceptions.IPCException;
import com.aws.greengrass.ipc.services.common.ApplicationMessage;
import com.aws.greengrass.ipc.services.secret.GetSecretValueRequest;
import com.aws.greengrass.ipc.services.secret.SecretClientOpCodes;
import com.aws.greengrass.ipc.services.secret.SecretGenericResponse;
import com.aws.greengrass.ipc.services.secret.SecretResponseStatus;
import com.aws.greengrass.lifecyclemanager.PluginService;
import com.aws.greengrass.secretmanager.exception.NoSecretFoundException;
import com.aws.greengrass.secretmanager.exception.SecretManagerException;
import com.aws.greengrass.secretmanager.exception.v1.GetSecretException;
import com.aws.greengrass.secretmanager.model.GetSecretResponse;
import com.aws.greengrass.secretmanager.model.SecretConfiguration;
import com.aws.greengrass.secretmanager.model.v1.GetSecretValueError;
import com.aws.greengrass.util.Coerce;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import generated.software.amazon.awssdk.iot.greengrass.model.GetSecretValueResponse;
import generated.software.amazon.awssdk.iot.greengrass.model.ResourceNotFoundError;
import generated.software.amazon.awssdk.iot.greengrass.model.ServiceError;
import generated.software.amazon.awssdk.iot.greengrass.model.UnauthorizedError;

import java.io.IOException;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
import javax.inject.Inject;

import static com.aws.greengrass.componentmanager.KernelConfigResolver.PARAMETERS_CONFIG_KEY;

@ImplementsService(name = SecretManagerService.SECRET_MANAGER_SERVICE_NAME)
public class SecretManagerService extends PluginService {

    public static final String SECRET_MANAGER_SERVICE_NAME = "aws.greengrass.SecretManager";
    public static final String SECRETS_TOPIC = "cloudSecrets";
    public static final String SECRETS_AUTHORIZATION_OPCODE = "getsecret";
    private static final ObjectMapper CBOR_MAPPER = new CBORMapper();
    private static final ObjectMapper OBJECT_MAPPER =
            new ObjectMapper().configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);

    private static final Map<SecretClientOpCodes, String> sdkToAuthCode;
    private final SecretManager secretManager;
    private final IPCRouter router;
    private AuthorizationHandler authorizationHandler;

    static {
        sdkToAuthCode = new EnumMap<>(SecretClientOpCodes.class);
        sdkToAuthCode.put(SecretClientOpCodes.GET_SECRET, SECRETS_AUTHORIZATION_OPCODE);
    }

    /**
     * Constructor for SecretManagerService Service.
     * @param topics                root Configuration topic for this service
     * @param router                router for registering the IPC callback
     * @param secretManager         secret manager which manages secrets
     * @param authorizationHandler  authorization handler
     */
    @Inject
    public SecretManagerService(Topics topics,
                                IPCRouter router,
                                SecretManager secretManager,
                                AuthorizationHandler authorizationHandler) {
        super(topics);
        this.router = router;
        this.secretManager = secretManager;
        this.authorizationHandler = authorizationHandler;
        // TODO: Subscribe on thing key updates
        topics.lookup(PARAMETERS_CONFIG_KEY, SECRETS_TOPIC)
                .subscribe(this::serviceChanged);
    }

    private void serviceChanged(WhatHappened whatHappened, Topic node) {
        String val = Coerce.toString(node);
        if (val == null) {
            logger.atInfo().kv("service", SECRET_MANAGER_SERVICE_NAME).log("No secrets configured");
            return;
        }
        try {
            List<SecretConfiguration> configuredSecrets =
                    OBJECT_MAPPER.readValue(val, new TypeReference<List<SecretConfiguration>>(){});
            secretManager.syncFromCloud(configuredSecrets);
        } catch (IOException e) {
            logger.atWarn().kv("node", SECRETS_TOPIC).kv("value", val).setCause(e)
                    .log("Unable to parse secrets configured");
        } catch (SecretManagerException e) {
            logger.atWarn().kv("service", SECRET_MANAGER_SERVICE_NAME).setCause(e)
                    .log("Unable to download secrets from cloud");
            serviceErrored(e);
        }
    }

    @Override
    public void postInject() {
        BuiltInServiceDestinationCode destination = BuiltInServiceDestinationCode.SECRET;
        super.postInject();
        try {
            authorizationHandler.registerComponent(this.getName(), new HashSet<>(
                    Arrays.asList(SECRETS_AUTHORIZATION_OPCODE)));
        } catch (AuthorizationException e) {
            logger.atError("initialize-secret-authorization-error", e)
                    .kv(IPCRouter.DESTINATION_STRING, destination.name())
                    .log("Failed to initialize the secret service with the Authorization module.");
        }

        try {
            router.registerServiceCallback(destination.getValue(), this::handleMessage);
            logger.atInfo().setEventType("ipc-register-request-handler").addKeyValue("destination", destination.name())
                    .log();
        } catch (IPCException e) {
            //TODO: validate why this is called multiple times
        }
    }

    @Override
    protected void startup() {
        // TODO: Modify secret service to only provide interface to deal with downloaded
        // secrets during download phase.

        // Since we have a valid directory, now try to load secrets if secrets file exists
        // We dont want to load anything if there is no file, which could happen when
        // we were not able to download any secrets due to network issues.
        try {
            secretManager.loadSecretsFromLocalStore();
        } catch (NoSecretFoundException e) {
            // Ignore. This means we started with empty configuration
            logger.atDebug().setEventType("secret-manager-startup").log("No secrets configured");
        } catch (SecretManagerException e) {
            serviceErrored(e);
            return;
        }
        reportState(State.RUNNING);
    }

    /**
     * Handles secret API calls from lambda-manager for v1 style lambdas.
     * @param serviceName  Lambda component name requesting the secret.
     * @param request      v1 style get secret request
     * @return secret      v1 style secret response
     */
    public GetSecretResponse getSecret(String serviceName, byte[] request) {
        int status;
        String message = null;
        try {
            com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest getSecretValueRequest = CBOR_MAPPER
                    .readValue(request, com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest.class);
            validateSecretIdAndDoAuthorization(SECRETS_AUTHORIZATION_OPCODE, serviceName,
                    getSecretValueRequest.getSecretId());
            logger.atInfo().event("secret-access").kv("Principal", serviceName)
                    .kv("secret", getSecretValueRequest.getSecretId()).log("requested secret");
            return GetSecretResponse.builder().secret(secretManager.getSecret(getSecretValueRequest)).build();
        } catch (GetSecretException t) {
            status = t.getStatus();
            message = t.getMessage();
        } catch (AuthorizationException t) {
            status = 403;
            message = t.getMessage();
        } catch (IOException t) {
            status = 400;
            message = "Unable to parse request";
        } catch (Throwable t) {
            status = 500;
            message = t.getMessage();
        }
        return GetSecretResponse.builder().error(GetSecretValueError.builder().status(status).message(message)
                .build()).build();
    }

    /**
     * Handles secret API calls from new IPC.
     *
     * @param request     get secret request from IPC API
     * @param serviceName component name of the request
     * @return get secret response for IPC API
     * @throws UnauthorizedError     if secret access is not authorized
     * @throws ResourceNotFoundError if requested secret is not found locally
     * @throws ServiceError          if kernel encountered errors while processing this request
     */
    public GetSecretValueResponse handleIPCRequest(
            generated.software.amazon.awssdk.iot.greengrass.model.GetSecretValueRequest request, String serviceName) {
        try {
            doAuthorization(sdkToAuthCode.get(SecretClientOpCodes.GET_SECRET), serviceName, request.getSecretId());
            logger.atInfo().event("secret-access").kv("Principal", serviceName).kv("secret", request.getSecretId())
                    .log("requested secret");
            return secretManager.getSecret(request);
        } catch (AuthorizationException e) {
            throw new UnauthorizedError(e.getMessage());
        } catch (GetSecretException e) {
            if (e.getStatus() == 404) {
                ResourceNotFoundError rnf = new ResourceNotFoundError();
                rnf.setMessage(e.getMessage());
                rnf.setResourceType("secret");
                throw new ResourceNotFoundError();
            }
            throw new ServiceError(e.getMessage());
        } catch (Exception e) {
            logger.atError("Internal error");
            throw new ServiceError(e.getMessage());
        }
    }

    /**
     * Handles secret API calls from IPC.
     * @param message  API message received from a client.
     * @param context  connection context received from a client.
     * @return API response as IPC frame
     */
    public Future<FrameReader.Message> handleMessage(FrameReader.Message message, ConnectionContext context) {
        CompletableFuture<FrameReader.Message> fut = new CompletableFuture<>();
        ApplicationMessage applicationMessage = ApplicationMessage.fromBytes(message.getPayload());
        try {
            SecretClientOpCodes opCode = SecretClientOpCodes.values()[applicationMessage.getOpCode()];
            SecretGenericResponse response = new SecretGenericResponse();
            switch (opCode) {
                case GET_SECRET:
                    GetSecretValueRequest request =
                            CBOR_MAPPER.readValue(applicationMessage.getPayload(), GetSecretValueRequest.class);
                    validateSecretIdAndDoAuthorization(sdkToAuthCode.get(opCode), context.getServiceName(),
                            request.getSecretId());
                    logger.atInfo().event("secret-access").kv("Principal", context.getServiceName())
                            .kv("secret", request.getSecretId()).log("requested secret");
                    response = secretManager.getSecret(request);
                    response.setStatus(SecretResponseStatus.Success);
                    break;
                default:
                    response.setStatus(SecretResponseStatus.InvalidRequest);
                    response.setErrorMessage("Unknown request type " + opCode.toString());
                    break;
            }
            ApplicationMessage responseMessage = ApplicationMessage.builder().version(applicationMessage.getVersion())
                    .payload(CBOR_MAPPER.writeValueAsBytes(response)).build();
            fut.complete(new FrameReader.Message(responseMessage.toByteArray()));
        } catch (Throwable t) {
            logger.atError().setEventType("secret-error").setCause(t).log("Failed to handle message");
            SecretResponseStatus status = SecretResponseStatus.InternalError;
            if (t instanceof AuthorizationException) {
                status = SecretResponseStatus.Unauthorized;
            }
            if (t instanceof GetSecretException) {
                status = SecretResponseStatus.InvalidRequest;
            }
            SecretGenericResponse response = new SecretGenericResponse(status, t.getMessage());
            try {
                ApplicationMessage responseMessage =
                        ApplicationMessage.builder().version(applicationMessage.getVersion())
                                .payload(CBOR_MAPPER.writeValueAsBytes(response)).build();
                fut.complete(new FrameReader.Message(responseMessage.toByteArray()));
            } catch (IOException ex) {
                logger.atError("secret-error", ex).log("Failed to send error response");
            }
        }
        if (!fut.isDone()) {
            fut.completeExceptionally(new IPCException("Unable to serialize any responses"));
        }
        return fut;
    }

    private void validateSecretIdAndDoAuthorization(String opCode, String serviceName, String secretId)
            throws AuthorizationException, GetSecretException {
        String arn = secretManager.validateSecretId(secretId);
        doAuthorization(opCode, serviceName, arn);
    }

    private void doAuthorization(String opCode, String serviceName, String secretId) throws AuthorizationException {
        authorizationHandler.isAuthorized(
                this.getName(),
                Permission.builder()
                        .principal(serviceName)
                        .operation(opCode.toLowerCase())
                        .resource(secretId)
                        .build());
    }

}
