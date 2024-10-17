/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager;

import com.aws.greengrass.authorization.AuthorizationHandler;
import com.aws.greengrass.authorization.exceptions.AuthorizationException;
import com.aws.greengrass.config.ChildChanged;
import com.aws.greengrass.config.Topics;
import com.aws.greengrass.config.WhatHappened;
import com.aws.greengrass.dependency.ImplementsService;
import com.aws.greengrass.dependency.State;
import com.aws.greengrass.lifecyclemanager.PluginService;
import com.aws.greengrass.secretmanager.exception.NoSecretFoundException;
import com.aws.greengrass.secretmanager.exception.SecretManagerException;
import com.aws.greengrass.secretmanager.exception.v1.GetSecretException;
import com.aws.greengrass.secretmanager.model.v1.GetSecretValueError;
import com.aws.greengrass.secretmanager.model.v1.GetSecretValueResult;
import com.aws.greengrass.util.Coerce;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Setter;
import software.amazon.awssdk.aws.greengrass.GreengrassCoreIPCService;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import javax.inject.Inject;

import static com.aws.greengrass.componentmanager.KernelConfigResolver.CONFIGURATION_CONFIG_KEY;
import static software.amazon.awssdk.aws.greengrass.GreengrassCoreIPCService.GET_SECRET_VALUE;

@ImplementsService(name = SecretManagerService.SECRET_MANAGER_SERVICE_NAME)
public class SecretManagerService extends PluginService {
    public static final String SECRET_MANAGER_SERVICE_NAME = "aws.greengrass.SecretManager";
    public static final String SECRETS_TOPIC = "cloudSecrets";
    public static final String PERIODIC_REFRESH_INTERVAL_MIN = "periodicRefreshIntervalMin";
    public static final String PERFORMANCE_TOPIC = "performance";
    public static final String CLOUD_REQUEST_QUEUE_SIZE_TOPIC = "cloudRequestQueueSize";

    private static final ObjectMapper OBJECT_MAPPER =
            new ObjectMapper().configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);

    private final SecretManager secretManager;
    private final AuthorizationHandler authorizationHandler;
    private ScheduledFuture<?> scheduledSyncFuture = null;
    private final Object scheduleSyncFutureLockObject = new Object();
    private final ScheduledExecutorService ses;
    private final ChildChanged handleConfigurationChangeLambda = (whatHappened, node) -> {
        if (whatHappened == WhatHappened.timestampUpdated || whatHappened == WhatHappened.interiorAdded) {
            return;
        }
        if (whatHappened == WhatHappened.initialized || SECRETS_TOPIC.equals(node.getName())
                || PERIODIC_REFRESH_INTERVAL_MIN.equals(node.getName())) {
            serviceChanged();
        }

        if (node != null && CLOUD_REQUEST_QUEUE_SIZE_TOPIC.equals(node.getName())) {
            requestReinstall();
        }
    };
    @Inject
    SecretManagerIPCAgent secretManagerIPCAgent;
    @Inject
    private GreengrassCoreIPCService greengrassCoreIPCService;
    // for testing
    @Setter
    private CountDownLatch isInitialSyncComplete = new CountDownLatch(1);

    /**
     * Constructor for SecretManagerService Service.
     *
     * @param topics               root Configuration topic for this service
     * @param secretManager        secret manager which manages secrets
     * @param authorizationHandler authorization handler
     * @param ses scheduled executor service
     */
    @Inject
    public SecretManagerService(Topics topics, SecretManager secretManager, AuthorizationHandler authorizationHandler,
                                ScheduledExecutorService ses) {
        super(topics);
        this.secretManager = secretManager;
        this.authorizationHandler = authorizationHandler;
        this.ses = ses;
    }

    @Override
    protected void install() throws InterruptedException {
        super.install();
        // Re-initialize the sync counter every time the component is installed
        setIsInitialSyncComplete(new CountDownLatch(1));
        // subscribe will invoke serviceChanged right away to sync from cloud
        this.config.lookupTopics(CONFIGURATION_CONFIG_KEY).subscribe(this.handleConfigurationChangeLambda);
        // Re-initialize the cloud thread pool for ipc async request processing
        secretManagerIPCAgent.setCloudCallThreadPool(config);
    }

    private void serviceChanged() {
        synchronized (scheduleSyncFutureLockObject) {
            if (scheduledSyncFuture != null) {
                scheduledSyncFuture.cancel(false);
                scheduledSyncFuture = null;
            }
            long refreshIntervalSeconds = (long) (Coerce.toDouble(
                    this.config.lookupTopics(CONFIGURATION_CONFIG_KEY).findOrDefault(0, PERIODIC_REFRESH_INTERVAL_MIN))
                    * 60);
            Runnable syncSecrets = () -> {
                secretManager.syncFromCloud();
                isInitialSyncComplete.countDown();
            };
            if (refreshIntervalSeconds <= 0) {
                // Refresh secrets only once and return
                syncSecrets.run();
            } else {
                // Schedule syncing secrets at configured intervals
                scheduledSyncFuture = ses.scheduleAtFixedRate(() -> {
                    try {
                        syncSecrets.run();
                    } catch (Exception ex) {
                        // Scheduler future will not run scheduled tasks if one of them is completed with an exception.
                        // This is to ensure that unknown exceptions are also caught so the scheduler keeps on running
                        logger.atError().cause(ex).log("Unable to sync configured secrets from cloud");
                    }
                }, 0, refreshIntervalSeconds, TimeUnit.SECONDS);
            }
        }
    }

    @Override
    protected void shutdown() {
        logger.atDebug().log("Shutting down secrets manager");
        synchronized (scheduleSyncFutureLockObject) {
            if (scheduledSyncFuture != null) {
                scheduledSyncFuture.cancel(true);
                scheduledSyncFuture = null;
            }
        }
        logger.atDebug().log("Done shutting down secrets manager");
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
        // Wait for the initial sync to complete before marking ourselves as running.
        // This will throw timeout exception as startup has default timeout of 2 minutes.
        isInitialSyncComplete.await();
        // GG_NEEDS_REVIEW: TODO: Modify secret service to only provide interface to deal with downloaded
        // secrets during download phase.

        // Since we have a valid directory, now try to load secrets if secrets file exists
        // We don't want to load anything if there is no file, which could happen when
        // we were not able to download any secrets due to network issues.
        try {
            secretManager.reloadCache();
        } catch (NoSecretFoundException e) {
            // Ignore. This means we started with empty configuration
            logger.atDebug().setEventType("secret-manager-startup").log("No secrets configured");
        } catch (SecretManagerException e) {
            logger.atWarn().setEventType("secret-manager-startup").log("Unable to reload secrets from cache "
                    + "during startup");
        } catch (Exception e) {
            // Put the service in ERRORED state if something unexpected happens. This should never happen.
            serviceErrored(e);
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
