package com.aws.iot.greengrass.secretmanager;

import com.aws.iot.evergreen.config.Topic;
import com.aws.iot.evergreen.config.Topics;
import com.aws.iot.evergreen.config.WhatHappened;
import com.aws.iot.evergreen.dependency.ImplementsService;
import com.aws.iot.evergreen.dependency.State;
import com.aws.iot.evergreen.ipc.ConnectionContext;
import com.aws.iot.evergreen.ipc.IPCRouter;
import com.aws.iot.evergreen.ipc.common.BuiltInServiceDestinationCode;
import com.aws.iot.evergreen.ipc.common.FrameReader;
import com.aws.iot.evergreen.ipc.exceptions.IPCException;
import com.aws.iot.evergreen.ipc.services.common.ApplicationMessage;
import com.aws.iot.evergreen.ipc.services.secret.GetSecretValueRequest;
import com.aws.iot.evergreen.ipc.services.secret.SecretClientOpCodes;
import com.aws.iot.evergreen.ipc.services.secret.SecretGenericResponse;
import com.aws.iot.evergreen.ipc.services.secret.SecretResponseStatus;
import com.aws.iot.evergreen.kernel.EvergreenService;
import com.aws.iot.evergreen.util.Coerce;
import com.aws.iot.greengrass.secretmanager.exception.SecretManagerException;
import com.aws.iot.greengrass.secretmanager.kernel.KernelClient;
import com.aws.iot.greengrass.secretmanager.model.SecretConfiguration;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
import javax.inject.Inject;

import static com.aws.iot.evergreen.deployment.bootstrap.BootstrapSuccessCode.REQUEST_RESTART;
import static com.aws.iot.evergreen.packagemanager.KernelConfigResolver.PARAMETERS_CONFIG_KEY;

@ImplementsService(name = SecretManagerService.SECRET_MANAGER_SERVICE_NAME)
public class SecretManagerService extends EvergreenService {

    public static final String SECRET_MANAGER_SERVICE_NAME = "aws.greengrass.secret.manager";
    public static final String SECRETS_TOPIC = "cloudSecrets";
    private static final ObjectMapper CBOR_MAPPER = new CBORMapper();
    private static final ObjectMapper OBJECT_MAPPER =
            new ObjectMapper().configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);

    private List<SecretConfiguration> configuredSecrets = new ArrayList<>();
    private final SecretManager secretManager;
    private final IPCRouter router;
    private final KernelClient kernelClient;

    /**
     * Constructor for SecretManagerService Service.
     * @param topics        root Configuration topic for this service
     * @param router        router for registering the IPC callback
     * @param kernelClient  Kernel client for accessing kernel state and methods
     * @param secretManager secret manager which manages secrets
     */
    @Inject
    public SecretManagerService(Topics topics,
                                IPCRouter router,
                                SecretManager secretManager,
                                KernelClient kernelClient) {
        super(topics);
        this.router = router;
        this.secretManager = secretManager;
        this.kernelClient = kernelClient;
        // TODO: Subscribe on thing key updates
        topics.lookup(PARAMETERS_CONFIG_KEY, SECRETS_TOPIC)
                .subscribe(this::serviceChanged);
    }

    private void serviceChanged(WhatHappened whatHappened, Topic node) {
        // TODO: reload secrets on deployment even if secrets dont change
        String val = Coerce.toString(node);
        if (val == null) {
            logger.atInfo().kv("service", SECRET_MANAGER_SERVICE_NAME).log("No secrets configured");
            return;
        }
        try {
            configuredSecrets = OBJECT_MAPPER.readValue(val, new TypeReference<List<SecretConfiguration>>(){});
            secretManager.syncFromCloud(configuredSecrets);
        } catch (IOException e) {
            logger.atWarn().kv("node", SECRETS_TOPIC).kv("value", val).setCause(e)
                    .log("Unable to parse secrets configured");
        } catch (SecretManagerException e) {
            logger.atWarn().kv("service", SECRET_MANAGER_SERVICE_NAME).setCause(e)
                    .log("Unable to download secrets from cloud");
        }
    }

    @Override
    public void postInject() {
        BuiltInServiceDestinationCode destination = BuiltInServiceDestinationCode.SECRET;
        super.postInject();
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
        } catch (SecretManagerException e) {
            serviceErrored(e);
            return;
        }
        reportState(State.RUNNING);
    }

    @Override
    public int bootstrap() {
        return REQUEST_RESTART;
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
            logger.atError().setEventType("secret-ipc-error").setCause(t).log("Failed to handle message");
            try {
                SecretGenericResponse response =
                        new SecretGenericResponse(SecretResponseStatus.InternalError, t.getMessage());
                ApplicationMessage responseMessage =
                        ApplicationMessage.builder().version(applicationMessage.getVersion())
                                .payload(CBOR_MAPPER.writeValueAsBytes(response)).build();
                fut.complete(new FrameReader.Message(responseMessage.toByteArray()));
            } catch (IOException ex) {
                logger.atError("secret-ipc-error", ex).log("Failed to send error response");
            }
        }
        if (!fut.isDone()) {
            fut.completeExceptionally(new IPCException("Unable to serialize any responses"));
        }
        return fut;
    }

}
