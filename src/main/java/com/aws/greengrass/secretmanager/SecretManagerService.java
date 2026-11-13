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
import software.amazon.awssdk.aws.greengrass.GreengrassCoreIPCService;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
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
    // The one-shot or the periodic sync, whichever the configured refresh interval selected
    private Future<?> syncFuture = null;
    // Guarded by scheduleSyncFutureLockObject. False until startup() has loaded the cache from the local store. No
    // cloud sync is started before then, so a download can never race the reload.
    private boolean cacheLoaded = false;
    private final Object scheduleSyncFutureLockObject = new Object();
    private final ScheduledExecutorService ses;
    private final ChildChanged handleConfigurationChangeLambda = (whatHappened, node) -> {
        if (whatHappened == WhatHappened.timestampUpdated || whatHappened == WhatHappened.interiorAdded) {
            return;
        }
        if (whatHappened == WhatHappened.initialized) {
            // Topics.subscribe passes a null node when it invokes the watcher on initialization
            serviceChanged();
            return;
        }
        if (node == null) {
            return;
        }
        if (SECRETS_TOPIC.equals(node.getName()) || PERIODIC_REFRESH_INTERVAL_MIN.equals(node.getName())) {
            serviceChanged();
        }
        if (CLOUD_REQUEST_QUEUE_SIZE_TOPIC.equals(node.getName())) {
            requestReinstall();
        }
    };
    @Inject
    SecretManagerIPCAgent secretManagerIPCAgent;
    @Inject
    private GreengrassCoreIPCService greengrassCoreIPCService;

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
        // install() re-runs without an intervening shutdown() when it errors or times out, so clear any sync left
        // over from the previous attempt. startup() reloads the cache again, so gate the cloud sync until it has.
        synchronized (scheduleSyncFutureLockObject) {
            cancelSync(true);
            cacheLoaded = false;
        }
        // subscribe invokes serviceChanged right away, which only records the config: startup() starts the sync
        this.config.lookupTopics(CONFIGURATION_CONFIG_KEY).subscribe(this.handleConfigurationChangeLambda);
        // Re-initialize the cloud thread pool for ipc async request processing
        secretManagerIPCAgent.setCloudCallThreadPool(config);
    }

    private void cancelSync(boolean interrupt) {
        if (syncFuture != null) {
            syncFuture.cancel(interrupt);
            syncFuture = null;
        }
    }

    private void serviceChanged() {
        synchronized (scheduleSyncFutureLockObject) {
            cancelSync(false);
            if (!cacheLoaded) {
                // startup() starts the sync itself once the cache is loaded, using the latest configuration
                return;
            }
            scheduleSyncFromCloud();
        }
    }

    /**
     * Start syncing secrets from cloud using the currently configured refresh interval. An interval of zero or less
     * means sync once; anything else schedules a periodic sync. Must be called holding scheduleSyncFutureLockObject,
     * with any previously scheduled sync already cancelled.
     */
    private void scheduleSyncFromCloud() {
        long refreshIntervalSeconds = (long) (Coerce.toDouble(
                this.config.lookupTopics(CONFIGURATION_CONFIG_KEY).findOrDefault(0, PERIODIC_REFRESH_INTERVAL_MIN))
                * 60);
        Runnable syncSecrets = () -> {
            try {
                secretManager.syncFromCloud();
            } catch (RuntimeException e) {
                if (Thread.currentThread().isInterrupted()) {
                    // Cancelled by shutdown or reinstall, not a failure
                    logger.atDebug().cause(e).log("Interrupted while syncing secrets from cloud");
                    return;
                }
                // Secret manager handles and logs the failures another pass can recover from: an unreachable cloud,
                // an unparseable configuration, a corrupt local store. Anything that reaches here is not one of
                // those, and retrying will not clear it, so error the service rather than quietly serving whatever
                // happens to be cached.
                serviceErrored(e);
            }
        };

        if (refreshIntervalSeconds <= 0) {
            // Refresh secrets only once and return
            syncFuture = ses.submit(syncSecrets);
        } else {
            // Schedule syncing secrets at configured intervals
            syncFuture = ses.scheduleAtFixedRate(syncSecrets, 0, refreshIntervalSeconds, TimeUnit.SECONDS);
        }
    }

    @Override
    protected void shutdown() {
        logger.atDebug().log("Shutting down secrets manager");
        synchronized (scheduleSyncFutureLockObject) {
            cancelSync(true);
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
        // Load the cache from the local store, then start the cloud sync and mark ourselves RUNNING. RUNNING means we
        // are accepting requests, not that every secret is current: the cloud download runs in the background and
        // must not delay startup. Starting the sync here, rather than from the config subscription in install(), is
        // what guarantees a download never races the reload below.

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
        synchronized (scheduleSyncFutureLockObject) {
            // Cancel the sync from a previous startup: startup() re-runs without install() when it errors
            cancelSync(false);
            cacheLoaded = true;
            scheduleSyncFromCloud();
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
        String message;

        try {
            com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest getSecretValueRequest =
                    OBJECT_MAPPER.readValue(request,
                            com.aws.greengrass.secretmanager.model.v1.GetSecretValueRequest.class);
            secretManagerIPCAgent.validateSecretIdAndDoAuthorization(GET_SECRET_VALUE,
                    serviceName,
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
