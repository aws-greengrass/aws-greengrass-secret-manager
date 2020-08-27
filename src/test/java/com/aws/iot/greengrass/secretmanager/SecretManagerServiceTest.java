package com.aws.iot.greengrass.secretmanager;

import com.aws.iot.evergreen.dependency.State;
import com.aws.iot.evergreen.ipc.ConnectionContext;
import com.aws.iot.evergreen.ipc.common.FrameReader;
import com.aws.iot.evergreen.ipc.services.common.ApplicationMessage;
import com.aws.iot.evergreen.ipc.services.common.IPCUtil;
import com.aws.iot.evergreen.ipc.services.secret.GetSecretValueResult;
import com.aws.iot.evergreen.ipc.services.secret.SecretClientOpCodes;
import com.aws.iot.evergreen.ipc.services.secret.SecretResponseStatus;
import com.aws.iot.evergreen.kernel.EvergreenService;
import com.aws.iot.evergreen.kernel.Kernel;
import com.aws.iot.evergreen.testcommons.testutilities.EGExtension;
import com.aws.iot.greengrass.secretmanager.exception.SecretManagerException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static com.aws.iot.evergreen.testcommons.testutilities.ExceptionLogProtector.ignoreExceptionOfType;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

@ExtendWith({MockitoExtension.class, EGExtension.class})
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

    @BeforeEach
    void setup() throws IOException {
        // create secrets directory by default
        Files.createDirectories(rootDir.resolve(FileSecretDao.SECRETS_DIR));
        Files.createFile(rootDir.resolve(FileSecretDao.SECRETS_DIR).resolve(FileSecretDao.SECRET_FILE));
    }

    void startKernelWithConfig(String configFile, State expectedState) throws InterruptedException {
        CountDownLatch secretManagerRunning = new CountDownLatch(1);
        kernel = new Kernel();
        kernel.parseArgs("-r", rootDir.toAbsolutePath().toString(), "-i", getClass().getResource(configFile).toString());
        kernel.getContext().addGlobalStateChangeListener((EvergreenService service, State was, State newState) -> {
            if (service.getName().equals(SecretManagerService.SECRET_MANAGER_SERVICE_NAME) && service.getState().equals(expectedState)) {
                secretManagerRunning.countDown();
            }
        });
        kernel.getContext().put(SecretManager.class, mockSecretManager);
        kernel.launch();
        assertTrue(secretManagerRunning.await(10, TimeUnit.SECONDS));
    }

    @AfterEach
    void cleanup() {
        kernel.shutdown();
    }

    private FrameReader.Message getInputMessage() throws IOException {
        com.aws.iot.evergreen.ipc.services.secret.GetSecretValueRequest request =
                com.aws.iot.evergreen.ipc.services.secret.GetSecretValueRequest.builder().secretId("name1").build();
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
    void GIVEN_secret_service_WHEN_load_secret_fails_THEN_service_errors() throws Exception {
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
        com.aws.iot.evergreen.ipc.services.secret.GetSecretValueResult mockSecretResponse1 =
                com.aws.iot.evergreen.ipc.services.secret.GetSecretValueResult.builder().secretString("secret1")
                .secretId(SECRET_ID)
                .versionId(VERSION_ID)
                .versionStages(Arrays.asList(new String[]{CURRENT_LABEL, VERSION_LABEL}))
                .build();

        when(mockSecretManager.getSecret(any())).thenReturn(mockSecretResponse1);

        FrameReader.Message inputMessage = getInputMessage();
        Future<FrameReader.Message> fut = kernel.getContext().get(SecretManagerService.class).handleMessage(inputMessage, mockContext);
        FrameReader.Message m = fut.get();
        com.aws.iot.evergreen.ipc.services.secret.GetSecretValueResult returnedResult =
                IPCUtil.decode(ApplicationMessage.fromBytes(m.getPayload()).getPayload(), GetSecretValueResult.class);
        assertEquals(SECRET_ID, returnedResult.getSecretId());
        assertEquals(VERSION_ID, returnedResult.getVersionId());
        assertThat(returnedResult.getVersionStages(), hasItem(CURRENT_LABEL));
        assertThat(returnedResult.getVersionStages(), hasItem(VERSION_LABEL));
        assertEquals(SecretResponseStatus.Success, returnedResult.getStatus());
    }

    @Test
    void GIVEN_secret_service_WHEN_handler_call_errors_out_THEN_correct_response_returned(ExtensionContext context) throws Exception {
        startKernelWithConfig("config.yaml", State.RUNNING);
        ignoreExceptionOfType(context, com.fasterxml.jackson.databind.exc.MismatchedInputException.class);
        FrameReader.Message inputMessage = getInvalidInputMessage();
        Future<FrameReader.Message> fut = kernel.getContext().get(SecretManagerService.class).handleMessage(inputMessage, mockContext);
        FrameReader.Message m = fut.get();
        com.aws.iot.evergreen.ipc.services.secret.GetSecretValueResult returnedResult =
                IPCUtil.decode(ApplicationMessage.fromBytes(m.getPayload()).getPayload(), GetSecretValueResult.class);
        assertEquals(SecretResponseStatus.InternalError, returnedResult.getStatus());
    }

}
