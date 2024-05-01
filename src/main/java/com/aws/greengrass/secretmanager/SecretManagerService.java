/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager;

import com.aws.greengrass.authorization.AuthorizationHandler;
import com.aws.greengrass.authorization.exceptions.AuthorizationException;
import com.aws.greengrass.config.ChildChanged;
import com.aws.greengrass.config.Topic;
import com.aws.greengrass.config.Topics;
import com.aws.greengrass.config.WhatHappened;
import com.aws.greengrass.dependency.ImplementsService;
import com.aws.greengrass.dependency.State;
import com.aws.greengrass.lifecyclemanager.PluginService;
import com.aws.greengrass.secretmanager.exception.NoSecretFoundException;
import com.aws.greengrass.secretmanager.exception.SecretCryptoException;
import com.aws.greengrass.secretmanager.exception.SecretManagerException;
import com.aws.greengrass.secretmanager.exception.v1.GetSecretException;
import com.aws.greengrass.secretmanager.model.SecretConfiguration;
import com.aws.greengrass.secretmanager.model.v1.GetSecretValueError;
import com.aws.greengrass.secretmanager.model.v1.GetSecretValueResult;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.aws.greengrass.GreengrassCoreIPCService;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;
import javax.inject.Inject;

import static com.aws.greengrass.componentmanager.KernelConfigResolver.CONFIGURATION_CONFIG_KEY;
import static software.amazon.awssdk.aws.greengrass.GreengrassCoreIPCService.GET_SECRET_VALUE;

@ImplementsService(name = SecretManagerService.SECRET_MANAGER_SERVICE_NAME)
public class SecretManagerService extends PluginService {
    public static final String SECRET_MANAGER_SERVICE_NAME = "aws.greengrass.SecretManager";
    public static final String SECRETS_TOPIC = "cloudSecrets";
    private static final ObjectMapper OBJECT_MAPPER =
            new ObjectMapper().configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);

    private final SecretManager secretManager;
    private final AuthorizationHandler authorizationHandler;
    private final ExecutorService executor;
    private final AtomicReference<Future<?>> syncFuture = new AtomicReference<Future<?>>(null);
    private final ChildChanged handleConfigurationChangeLambda = (whatHappened, node) -> {
        if (whatHappened == WhatHappened.timestampUpdated || whatHappened == WhatHappened.interiorAdded) {
            return;
        }
        if (whatHappened == WhatHappened.initialized || SECRETS_TOPIC.equals(node.getName())) {
            serviceChanged();
        }
    };

    @Inject
    SecretManagerIPCAgent secretManagerIPCAgent;

    @Inject
    private GreengrassCoreIPCService greengrassCoreIPCService;

    /**
     * Constructor for SecretManagerService Service.
     * @param topics                root Configuration topic for this service
     * @param secretManager         secret manager which manages secrets
     * @param authorizationHandler  authorization handler
     * @param executorService       executor service
     */
    @Inject
    public SecretManagerService(Topics topics,
                                SecretManager secretManager,
                                AuthorizationHandler authorizationHandler,
                                ExecutorService executorService) {
        super(topics);
        this.secretManager = secretManager;
        this.authorizationHandler = authorizationHandler;
        this.executor = executorService;
    }

    @Override
    protected void install() throws InterruptedException {
        super.install();
        // subscribe will invoke serviceChanged right away to sync from cloud
        // GG_NEEDS_REVIEW: TODO: Subscribe on thing key updates
        this.config.lookupTopics(CONFIGURATION_CONFIG_KEY).subscribe(this.handleConfigurationChangeLambda);
    }

    private void syncFromCloud() throws SecretManagerException, InterruptedException {
        Topic secretParam = this.config.lookup(CONFIGURATION_CONFIG_KEY, SECRETS_TOPIC);
        try {
            if (secretParam == null) {
                logger.atInfo().kv("service", SECRET_MANAGER_SERVICE_NAME).log("No secrets configured");
                secretManager.syncFromCloud(new ArrayList<>());
                return;
            }
            List<SecretConfiguration> configuredSecrets = OBJECT_MAPPER.convertValue(secretParam.toPOJO(),
                    new TypeReference<List<SecretConfiguration>>() {
                    });
            if (configuredSecrets != null) {
                secretManager.syncFromCloud(configuredSecrets);
            } else {
                logger.atError().kv("secrets", secretParam.toString()).log("Unable to parse secrets configured");
            }
        } catch (IllegalArgumentException e) {
            logger.atError().kv("node", secretParam == null ? null : secretParam.getFullName())
                    .kv("value", secretParam).setCause(e).log("Unable to parse secrets configured");
        }
    }

    private void serviceChanged() {
        replaceSyncFuture(() -> {
            try {
                this.syncFromCloud();
            } catch (SecretManagerException e) {
                logger.atWarn().kv("service", SECRET_MANAGER_SERVICE_NAME).setCause(e)
                        .log("Unable to download secrets from cloud");
                serviceErrored(e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
    }

    private synchronized Future<?> replaceSyncFuture(Runnable r) {
        Future<?> newFut = r == null ? null : executor.submit(r);
        Future<?> oldFut = syncFuture.getAndSet(newFut);
        if (oldFut != null) {
            oldFut.cancel(true);
        }
        return newFut;
    }

    @Override
    public void postInject() {
        super.postInject();
        try {
            authorizationHandler.registerComponent(this.getName(),
                    new HashSet<>(Collections.singletonList(GET_SECRET_VALUE)));
        } catch (AuthorizationException e) {
            logger.atError("initialize-secret-authorization-error", e)
                    .log("Failed to initialize the secret service with the Authorization module.");
        }

        greengrassCoreIPCService.setGetSecretValueHandler(
                context -> secretManagerIPCAgent.getSecretValueOperationHandler(context));
        logger.atInfo("ipc-register-request-handler").log();
    }

    @Override
    public void startup() throws InterruptedException {
        try {
            secretManager.waitForInitialization();
        } catch (SecretCryptoException e) {
            serviceErrored(e);
            return;
        }
        // Wait for the initial sync to complete before marking ourselves as running
        Future<?> syncFut = syncFuture.get();
        if (syncFut != null) {
            try {
                syncFut.get();
            } catch (ExecutionException ex) {
                serviceErrored(ex.getCause());
                return;
            }
        }

        // GG_NEEDS_REVIEW: TODO: Modify secret service to only provide interface to deal with downloaded
        // secrets during download phase.

        // Since we have a valid directory, now try to load secrets if secrets file exists
        // We don't want to load anything if there is no file, which could happen when
        // we were not able to download any secrets due to network issues.
        try {
            secretManager.loadSecretsFromLocalStore();
        } catch (NoSecretFoundException e) {
            // Ignore. This means we started with empty configuration
            logger.atDebug().setEventType("secret-manager-startup").log("No secrets configured");
        } catch (SecretManagerException e) {
            // No need to log anything here, it is already logged by loadSecretsFromLocalStore

            // If there was a crypto issue then we probably need to re-encrypt the secrets, so we will wait for the sync
            // future to complete without error since it would have started up already due to the subscribe() call
            // above.
            if (e.getCause() instanceof SecretCryptoException) {
                syncFut = syncFuture.get();
                if (syncFut != null) {
                    try {
                        syncFut.get();
                    } catch (ExecutionException ex) {
                        serviceErrored(ex.getCause());
                        return;
                    }
                }
            } else {
                serviceErrored(e);
                return;
            }
        }
        reportState(State.RUNNING);
    }

    /**
     * Handles secret API calls from lambda-manager for v1 style lambdas.
     * @param serviceName  Lambda component name requesting the secret.
     * @param request      v1 style get secret request
     * @return v1 style secret or error serialized as JSON bytes. If a serialization error occurs, null is returned.
     */
    // Note: Do not rename/move this method around as it is used via reflection from the lambda-manager.
    public byte[] getSecret(String serviceName, byte[] request) {
        logger.atInfo().event("secret-access")
                .kv("Principal", serviceName)
                .kv("secret", new String(request))
                .log("requested secret");

        int status;
        String message = null;

        try {
            com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest getSecretValueRequest =
                    OBJECT_MAPPER.readValue(request,
                            com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest.class);
            secretManagerIPCAgent.validateSecretIdAndDoAuthorization(GET_SECRET_VALUE, serviceName,
                    getSecretValueRequest.getSecretId());
            GetSecretValueResult response = secretManager.getSecret(getSecretValueRequest);

            try {
                return OBJECT_MAPPER.writeValueAsBytes(response);
            } catch (JsonProcessingException e) {
                // not logging exception in case it outputs secret value
                logger.atError().event("secret-access")
                        .kv("Principal", serviceName).kv("secret", new String(request))
                        .log("Error serializing secret");
                return null;
            }
        } catch (IOException e) {
            status = 400;
            message = "Unable to parse request";
        } catch (AuthorizationException t) {
            status = 403;
            message = t.getMessage();
        } catch (GetSecretException t) {
            status = t.getStatus();
            message = t.getMessage();
        } catch (Throwable t) {
            status = 500;
            message = t.getMessage();
            logger.atError().event("secret-access").setCause(t)
                    .kv("Principal", serviceName).kv("secret", new String(request))
                    .log("Error getting secret");
        }

        try {
            return OBJECT_MAPPER.writeValueAsBytes(GetSecretValueError.builder().status(status).message(message)
                    .build());
        } catch (JsonProcessingException e) {
            logger.atError().event("secret-access").setCause(e)
                    .kv("Principal", serviceName)
                    .kv("secret", new String(request))
                    .kv("status", status)
                    .kv("message", message)
                    .log("Error serializing error response");
            return null;
        }
    }
}
