/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager;

import com.aws.greengrass.authorization.AuthorizationHandler;
import com.aws.greengrass.authorization.Permission;
import com.aws.greengrass.authorization.exceptions.AuthorizationException;
import com.aws.greengrass.config.Topics;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import com.aws.greengrass.secretmanager.exception.v1.GetSecretException;
import com.aws.greengrass.util.Coerce;
import software.amazon.awssdk.aws.greengrass.GeneratedAbstractGetSecretValueOperationHandler;
import software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest;
import software.amazon.awssdk.aws.greengrass.model.GetSecretValueResponse;
import software.amazon.awssdk.aws.greengrass.model.ResourceNotFoundError;
import software.amazon.awssdk.aws.greengrass.model.ServiceError;
import software.amazon.awssdk.aws.greengrass.model.UnauthorizedError;
import software.amazon.awssdk.eventstreamrpc.OperationContinuationHandlerContext;
import software.amazon.awssdk.eventstreamrpc.model.EventStreamJsonMessage;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.inject.Inject;

import static com.aws.greengrass.componentmanager.KernelConfigResolver.CONFIGURATION_CONFIG_KEY;
import static com.aws.greengrass.secretmanager.SecretManagerService.CLOUD_REQUEST_QUEUE_SIZE_TOPIC;
import static com.aws.greengrass.secretmanager.SecretManagerService.PERFORMANCE_TOPIC;
import static software.amazon.awssdk.aws.greengrass.GreengrassCoreIPCService.GET_SECRET_VALUE;

/**
 * Class to handle business logic for all SecretManager requests over IPC.
 */
public class SecretManagerIPCAgent {
    private static final Logger logger = LogManager.getLogger(SecretManagerIPCAgent.class);
    private final SecretManager secretManager;
    private final AuthorizationHandler authorizationHandler;
    private static final int DEFAULT_CLOUD_REQUEST_SIZE = 100;
    //IPC requests that make cloud call are processed by a separate thread (main ipc event loop thread
    // is not blocked by these requests). These requests are queued and processed as they come in.
    private AtomicReference<ExecutorService> cloudCallThreadPool = new AtomicReference<>(null);
    private static final int DEFAULT_CORE_POOL_SIZE = 1;
    private static final int DEFAULT_MAX_POOL_SIZE = 1;
    private static final int DEFAULT_KEEP_ALIVE_TIMEOUT_SECONDS = 60;

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

    /**
     * Use secret manager config to set the cloud call thread pool size. If not configured, default value is used.
     *
     * @param config component configuration
     */
    public void setCloudCallThreadPool(Topics config) {
        int cloudCallQueueSize = Coerce.toInt(config.lookupTopics(CONFIGURATION_CONFIG_KEY, PERFORMANCE_TOPIC)
                .findOrDefault(DEFAULT_CLOUD_REQUEST_SIZE, CLOUD_REQUEST_QUEUE_SIZE_TOPIC));
        if (cloudCallQueueSize <= 0) {
            logger.atWarn().kv("queueSize", DEFAULT_CLOUD_REQUEST_SIZE)
                    .kv("configured", cloudCallQueueSize)
                    .log("Using default value for cloud request queue size as the configured value is invalid");
            cloudCallQueueSize = DEFAULT_CLOUD_REQUEST_SIZE;
        }
        ExecutorService oldThreadPool = cloudCallThreadPool.getAndSet(
                new ThreadPoolExecutor(DEFAULT_CORE_POOL_SIZE, DEFAULT_MAX_POOL_SIZE,
                        DEFAULT_KEEP_ALIVE_TIMEOUT_SECONDS, TimeUnit.SECONDS,
                        new LinkedBlockingQueue<>(cloudCallQueueSize)));
        if (oldThreadPool != null) {
            oldThreadPool.shutdownNow();
        }
    }

    public GetSecretValueOperationHandler getSecretValueOperationHandler(OperationContinuationHandlerContext context) {
        return new GetSecretValueOperationHandler(context);
    }

    /**
     * Validate the secret id and do authorization for the given operation.
     * If the secret is not found in the cache, it should be fetched from cloud and then validated.
     *
     * @param opCode operation
     * @param serviceName the component using this API
     * @param secretId the name of the secret
     * @return true if the component is authorized to operate on the secret. False if it cannot be determined
     *
     * @throws AuthorizationException If the secret is not authorized to be used by the component
     */
    public boolean validateSecretIdAndDoAuthorization(String opCode, String serviceName, String secretId)
            throws AuthorizationException {
        try {
            String arn = secretManager.validateSecretId(secretId);
            doAuthorization(opCode, serviceName, arn);
            return true;
        } catch (GetSecretException e) {
            logger.atDebug().kv("secret", secretId).kv("principal", serviceName).log("Could not validate the secret "
                    + "access as it is not found in the cache");
            return false;
        }
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
            logger.atDebug().log("ipc-get-secret-request");
            try {
                logger.atInfo().event("secret-access").kv("Principal", serviceName).kv("secret", request.getSecretId())
                        .log("requested secret");
                boolean isSecretValidated = validateSecretIdAndDoAuthorization(GET_SECRET_VALUE, serviceName,
                        request.getSecretId());
                GetSecretValueResponse response = secretManager.getSecret(request);
                if (!isSecretValidated) {
                    validateSecretIdAndDoAuthorization(GET_SECRET_VALUE, serviceName, request.getSecretId());
                }
                return response;
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
        public CompletableFuture<GetSecretValueResponse> handleRequestAsync(GetSecretValueRequest request) {
            // This should never be used
            cloudCallThreadPool.compareAndSet(null,
                    new ThreadPoolExecutor(DEFAULT_CORE_POOL_SIZE, DEFAULT_MAX_POOL_SIZE,
                            DEFAULT_KEEP_ALIVE_TIMEOUT_SECONDS, TimeUnit.SECONDS,
                            new LinkedBlockingQueue<>(DEFAULT_CLOUD_REQUEST_SIZE)));
            try {
                return CompletableFuture.supplyAsync(() -> handleRequest(request), cloudCallThreadPool.get());
            } catch (RejectedExecutionException e) {
                CompletableFuture<GetSecretValueResponse> fut = new CompletableFuture<>();
                logger.atWarn().kv("componentName", serviceName)
                        .log("Unable to queue GetSecretValueResponse. {}", e.getMessage());
                fut.completeExceptionally(new ServiceError("Unable to queue request"));
                return fut;
            }
        }

        @Override
        public void handleStreamEvent(EventStreamJsonMessage streamRequestEvent) {

        }
    }
}
