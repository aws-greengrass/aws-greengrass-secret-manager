package com.aws.iot.greengrass.secretmanager;

import com.aws.iot.evergreen.config.Topics;
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
import com.aws.iot.greengrass.secretmanager.model.SecretConfiguration;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import javax.inject.Inject;

import static com.aws.iot.evergreen.deployment.bootstrap.BootstrapSuccessCode.REQUEST_RESTART;
import static com.aws.iot.evergreen.packagemanager.KernelConfigResolver.PARAMETERS_CONFIG_KEY;

@ImplementsService(name = SecretManagerService.SECRET_MANAGER_SERVICE_NAME)
public class SecretManagerService extends EvergreenService {

    public static final String SECRET_MANAGER_SERVICE_NAME = "aws.greengrass.secret.manager";
    public static final String SECRETS_TOPIC = "secrets";
    private static final ObjectMapper CBOR_MAPPER = new CBORMapper();

    private List<String> configuredSecrets = new ArrayList<String>();
    private final SecretManager secretManager;

    private IPCRouter router;

    /**
     * Constructor for SecretManagerService Service.
     * @param topics        root Configuration topic for this service
     * @param router        router for registering the IPC callback
     * @param secretManager secret manager which manages secrets
     */
    @Inject
    public SecretManagerService(Topics topics,
                                IPCRouter router,
                                SecretManager secretManager) {
        super(topics);
        this.router = router;
        // TODO: Subscribe on secret changes
        topics.lookup(PARAMETERS_CONFIG_KEY, SECRETS_TOPIC)
                .subscribe((why, newv) ->
                        configuredSecrets = Coerce.toStringList(newv));
        this.secretManager = secretManager;
        // TODO: Setup persistent directories/permissions for local db
    }

    @Override
    public void install() {
        // TODO: Add support for label in confugration
        // TODO: move download to kernel downloader
        secretManager.syncFromCloud(configuredSecrets.stream()
                .map(r -> SecretConfiguration.builder().arn(r).build()).collect(Collectors.toList()));
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
        reportState(State.RUNNING);
    }

    @Override
    public int bootstrap() {
        return REQUEST_RESTART;
    }

    /**
     * Handles secret API calls from IPC.
     * @param message  API message recevied from a client.
     * @param context  connection context received from a client.
     * @return
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
