/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager;

import com.aws.greengrass.dependency.State;
import com.aws.greengrass.deployment.DeviceConfiguration;
import com.aws.greengrass.integrationtests.BaseITCase;
import com.aws.greengrass.integrationtests.ipc.IPCTestUtils;
import com.aws.greengrass.lifecyclemanager.GreengrassService;
import com.aws.greengrass.lifecyclemanager.Kernel;
import com.aws.greengrass.logging.impl.config.LogConfig;
import com.aws.greengrass.secretmanager.exception.SecretCryptoException;
import com.aws.greengrass.secretmanager.exception.SecretManagerException;
import com.aws.greengrass.secretmanager.exception.v1.GetSecretException;
import com.aws.greengrass.secretmanager.model.AWSSecretResponse;
import com.aws.greengrass.secretmanager.store.FileSecretStore;
import com.aws.greengrass.security.SecurityService;
import com.aws.greengrass.security.exceptions.KeyLoadingException;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import com.aws.greengrass.util.EncryptionUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.event.Level;
import software.amazon.awssdk.aws.greengrass.GreengrassCoreIPCClientV2;
import software.amazon.awssdk.aws.greengrass.model.GetSecretValueResponse;
import software.amazon.awssdk.aws.greengrass.model.ResourceNotFoundError;
import software.amazon.awssdk.aws.greengrass.model.ServiceError;
import software.amazon.awssdk.aws.greengrass.model.UnauthorizedError;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static com.aws.greengrass.componentmanager.KernelConfigResolver.CONFIGURATION_CONFIG_KEY;
import static com.aws.greengrass.deployment.DeviceConfiguration.DEVICE_PARAM_PRIVATE_KEY_PATH;
import static com.aws.greengrass.deployment.DeviceConfiguration.SYSTEM_NAMESPACE_KEY;
import static com.aws.greengrass.secretmanager.SecretManagerService.CLOUD_REQUEST_QUEUE_SIZE_TOPIC;
import static com.aws.greengrass.secretmanager.SecretManagerService.PERFORMANCE_TOPIC;
import static com.aws.greengrass.secretmanager.TestUtil.ignoreErrors;
import static com.aws.greengrass.testcommons.testutilities.ExceptionLogProtector.ignoreExceptionOfType;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

@ExtendWith({MockitoExtension.class, GGExtension.class})
public class SecretManagerServiceIntegTest extends BaseITCase {
    // Cloud fetches performed by one sync pass: config.yaml has Secret1 (labels "new" + AWSCURRENT) and partialarn
    // (AWSCURRENT), config_refresh.yaml has only Secret1. AWSCURRENT is always added if not configured.
    private static final int CONFIG_CLOUD_CALLS = 3;
    private static final int REFRESH_CONFIG_CLOUD_CALLS = 2;

    private final String VERSION_ID = "id";
    private final String CURRENT_LABEL = "AWSCURRENT";
    private Kernel kernel;
    private final SecurityService mockSecurityService = spy(new SecurityService(mock(DeviceConfiguration.class)));

    // The AWSCURRENT response for Secret1. Held in a reference rather than re-stubbed mid-test: with a periodic
    // refresh configured, a background sync can call the mock while Mockito is part-way through a new stubbing.
    private final AtomicReference<software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse>
            currentLabelResponse = new AtomicReference<>();

    // Every mocked cloud fetch counts down each registered latch, so a test can wait for a sync pass to finish
    // instead of sleeping. The service reports RUNNING before the first download completes, by design.
    private final List<CountDownLatch> cloudCallLatches = new CopyOnWriteArrayList<>();

    // Set to fail every cloud fetch, for tests that need the device to have no working connection
    private final AtomicBoolean cloudUnavailable = new AtomicBoolean(false);

    private CountDownLatch expectCloudCalls(int count) {
        CountDownLatch latch = new CountDownLatch(count);
        cloudCallLatches.add(latch);
        return latch;
    }

    private void countCloudCall() {
        cloudCallLatches.forEach(CountDownLatch::countDown);
    }

    private void failIfCloudUnavailable() throws SecretManagerException {
        if (cloudUnavailable.get()) {
            throw new SecretManagerException("cloud is unavailable");
        }
    }

    /**
     * Wait until a secret is resolvable from the cache. A sync's cloud fetch becomes observable just before it
     * finishes caching the secret and its name, so a read issued the instant the fetch is seen can still miss. Polls
     * the secret manager directly rather than over IPC, so a miss does not log an error and fail the test.
     */
    private void awaitSecretResolvable(String secretId) throws Exception {
        SecretManager secretManager = kernel.getContext().get(SecretManager.class);
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(10);
        while (true) {
            try {
                secretManager.validateSecretId(secretId);
                return;
            } catch (GetSecretException e) {
                if (System.currentTimeMillis() >= deadline) {
                    throw e;
                }
                Thread.sleep(50);
            }
        }
    }

    @TempDir
    Path rootDir;

    @Mock
    AWSSecretClient secretClient;

    void startKernelWithConfig(String configFile, State expectedState) throws Exception {
        startKernelWithConfig(configFile, expectedState, 0);
    }

    /**
     * Launch the kernel and wait until secret manager reaches expectedState and its first cloud sync has finished.
     *
     * @param expectedCloudCalls cloud fetches one sync pass makes for this config, or 0 to not wait for a sync
     */
    void startKernelWithConfig(String configFile, State expectedState, int expectedCloudCalls) throws Exception {
        URI privateKey = getClass().getResource("privateKey.pem").toURI();
        URI certUri = getClass().getResource("cert.pem").toURI();
        lenient().doReturn(privateKey).when(mockSecurityService).getDeviceIdentityPrivateKeyURI();
        lenient().doReturn(certUri).when(mockSecurityService).getDeviceIdentityCertificateURI();
        lenient().doReturn(EncryptionUtils.loadPrivateKeyPair(Paths.get(privateKey))).when(mockSecurityService).getKeyPair(privateKey, certUri);
        mockSecretResponse();
        CountDownLatch initialSyncComplete = expectCloudCalls(expectedCloudCalls);
        kernel = new Kernel();
        kernel.parseArgs("-r", rootDir.toAbsolutePath().toString(), "-i",
                getClass().getResource(configFile).toString());

        CountDownLatch secretManagerRunning = new CountDownLatch(1);
        kernel.getContext().addGlobalStateChangeListener((GreengrassService service, State was, State newState) -> {
            if (service.getName().equals(SecretManagerService.SECRET_MANAGER_SERVICE_NAME) && service.getState()
                    .equals(expectedState)) {
                secretManagerRunning.countDown();
            }
        });
        kernel.getContext().put(AWSSecretClient.class, secretClient);
        kernel.getContext().put(SecurityService.class, mockSecurityService);
        kernel.launch();

        assertTrue(secretManagerRunning.await(10, TimeUnit.SECONDS));
        // Secret manager reports RUNNING as soon as the local cache is reloaded; the cloud download runs in the
        // background. Wait for it before asserting on downloaded secrets, or re-stubbing the cloud mock.
        assertTrue(initialSyncComplete.await(10, TimeUnit.SECONDS), "initial cloud sync did not complete");
    }

    private void mockSecretResponse() throws SecretManagerException, IOException {
        String secretArn = "arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh";
        String secretName = "Secret1";
        currentLabelResponse.set(software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse.builder()
                .name(secretName).arn(secretArn).secretString("secretValue").versionId(VERSION_ID)
                .versionStages(CURRENT_LABEL)
                .createdDate(Instant.now().minusSeconds(1000000)).build());
        lenient().doAnswer(i -> {
            failIfCloudUnavailable();
            countCloudCall();
            return currentLabelResponse.get();
        }).when(secretClient).getSecret(GetSecretValueRequest.builder().secretId(secretArn).versionStage(CURRENT_LABEL).build());

        lenient().doAnswer(i -> {
            failIfCloudUnavailable();
            countCloudCall();
            return software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse.builder()
                    .name(secretName).arn(secretArn).secretString("secretValue2").versionId("id2")
                    .versionStages("new").createdDate(Instant.now().minusSeconds(1000000)).build();
        }).when(secretClient).getSecret(GetSecretValueRequest.builder().secretId(secretArn).versionStage("new").build());

        lenient().doAnswer(i -> {
            failIfCloudUnavailable();
            countCloudCall();
            return software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse.builder()
                    .name("partialarn")
                    .arn("arn:aws:secretsmanager:us-east-1:999936977227:secret:partialarn" + "-43lYMk")
                    .secretString("secretValue").versionId("partialarnid").versionStages(CURRENT_LABEL)
                    .createdDate(Instant.now().minusSeconds(1000000)).build();
        }).when(secretClient).getSecret(
                GetSecretValueRequest.builder()
                        .secretId("arn:aws:secretsmanager:us" + "-east-1:999936977227:secret:partialarn")
                        .versionStage(CURRENT_LABEL).build());
    }

    @AfterEach
    void clean() {
        kernel.shutdown();
    }

    @BeforeEach
    void setup(ExtensionContext context) {
        // Set this property for kernel to scan its own classpath to find plugins
        System.setProperty("aws.greengrass.scanSelfClasspath", "true");
        ignoreErrors(context);
    }

    @Test
    void GIVEN_secret_service_WHEN_started_with_bad_parameter_config_THEN_starts_successfully(ExtensionContext context)
            throws Exception {
        ignoreExceptionOfType(context, IllegalArgumentException.class);
        startKernelWithConfig("badConfig.yaml", State.RUNNING);
    }

    @Test
    void GIVEN_secret_service_WHEN_started_without_secrets_THEN_starts_successfully()
            throws Exception {
        startKernelWithConfig("emptyParameterConfig.yaml", State.RUNNING);
    }

    @Test
    void GIVEN_secret_service_WHEN_started_without_secret_entry_THEN_starts_successfully()
            throws Exception {
        startKernelWithConfig("emptySecretConfig.yaml", State.RUNNING);
    }

    @Test
    void GIVEN_secret_service_WHEN_request_invalid_THEN_correct_response_returned(ExtensionContext context)
            throws Exception {
        ignoreExceptionOfType(context, GetSecretException.class);
        startKernelWithConfig("config.yaml", State.RUNNING, CONFIG_CLOUD_CALLS);
        final String serviceName = "ComponentRequestingSecrets";

        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest req =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        req.setSecretId("");
        req.setVersionId(VERSION_ID);
        GreengrassCoreIPCClientV2 clientV2 = IPCTestUtils.connectV2Client(kernel, serviceName);
        ServiceError e = assertThrows(ServiceError.class, () -> clientV2.getSecretValue(req));
        assertThat(e.getMessage(), containsString("SecretId absent in the request"));
    }


    @Test
    void GIVEN_secret_service_And_device_config_changes_throw_ex_When_ipc_handler_called_THEN_return_from_cache() throws Exception {
        startKernelWithConfig("config.yaml", State.RUNNING, CONFIG_CLOUD_CALLS);
        lenient().doThrow(KeyLoadingException.class).when(mockSecurityService).getKeyPair(any(),
                any());
        kernel.getConfig().lookup(SYSTEM_NAMESPACE_KEY, DEVICE_PARAM_PRIVATE_KEY_PATH).withValue("someKey.pem");
        kernel.getContext().runOnPublishQueueAndWait(() -> {
        });
        // Assert that crypter is unavailable
        LocalStoreMap map = kernel.getContext().get(LocalStoreMap.class);
        assertThrows(SecretCryptoException.class, ()->map.getCrypter());
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest secretExists =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        secretExists.setSecretId("Secret1");
        secretExists.setVersionId(VERSION_ID);

        GreengrassCoreIPCClientV2 clientV2 = IPCTestUtils.connectV2Client(kernel, "ComponentRequestingSecrets");
        GetSecretValueResponse response= clientV2.getSecretValue(secretExists);
        assertEquals("arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh", response.getSecretId());
        assertEquals(VERSION_ID, response.getVersionId());
        assertTrue(response.getVersionStage().contains(CURRENT_LABEL));
        assertEquals("secretValue", response.getSecretValue().getSecretString());
    }

    @Test
    void GIVEN_secret_service_WHEN_security_service_unavailable_THEN_local_secret_persists_and_cache_updates(ExtensionContext context) throws Exception {
        startKernelWithConfig("config.yaml", State.RUNNING, CONFIG_CLOUD_CALLS);
        ignoreExceptionOfType(context, SecretCryptoException.class);
        ignoreExceptionOfType(context, GetSecretException.class);
        ignoreExceptionOfType(context, SecretManagerException.class);
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest secretExists =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        secretExists.setSecretId("Secret1");
        secretExists.setVersionId(VERSION_ID);
        GreengrassCoreIPCClientV2 clientV2 = IPCTestUtils.connectV2Client(kernel, "ComponentRequestingSecrets");
        // Secret exists in cache
        GetSecretValueResponse response= clientV2.getSecretValue(secretExists);
        assertEquals("arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh", response.getSecretId());
        assertEquals(VERSION_ID, response.getVersionId());
        assertTrue(response.getVersionStage().contains(CURRENT_LABEL));
        assertEquals("secretValue", response.getSecretValue().getSecretString());
        SecretManagerService service = kernel.getContext().get(SecretManagerService.class);
        // Keypair loading with ServiceUnavailableException takes 5 minutes to complete. So, fail keypair loading
        // with a non-retryable exception.
        lenient().doThrow(KeyLoadingException.class).when(mockSecurityService).getKeyPair(any(),
                any());
        // Change config, so that crypter is reloaded
        kernel.getConfig().lookup(SYSTEM_NAMESPACE_KEY, DEVICE_PARAM_PRIVATE_KEY_PATH).withValue("someKey.pem");
        kernel.getContext().runOnPublishQueueAndWait(() -> {
        });
        // Assert that crypter is unavailable
        LocalStoreMap map = kernel.getContext().get(LocalStoreMap.class);
        assertThrows(SecretCryptoException.class, ()->map.getCrypter());

        // Take the cloud away too. Startup starts a fresh sync, which would otherwise repopulate the in-memory cache
        // from cloud and mask whether the secret survived on disk. Crypter broken and no connectivity is the state
        // this test is about.
        cloudUnavailable.set(true);

        // Restart secret manager service so the in-memory cache of secrets cleared
        service.requestRestart();
        CountDownLatch secretManagerRun = new CountDownLatch(1);
        kernel.getContext().addGlobalStateChangeListener((GreengrassService services, State was, State newState) -> {
            if (services.getName().equals(SecretManagerService.SECRET_MANAGER_SERVICE_NAME) && services.getState()
                    .equals(State.RUNNING)) {
                secretManagerRun.countDown();
            }
        });
        secretManagerRun.await();

        // Then secrets still exist on disk
        FileSecretStore fs = kernel.getContext().get(FileSecretStore.class);
        AWSSecretResponse res = fs.get("arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh",
                CURRENT_LABEL);
        assertEquals("arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh",res.getArn());
        // The secret is not present in cache
        assertThrows(ResourceNotFoundError.class, ()->clientV2.getSecretValue(secretExists));

        // Make security service available without secret manager restart
        URI privateKey = getClass().getResource("privateKey.pem").toURI();
        lenient().doReturn(EncryptionUtils.loadPrivateKeyPair(Paths.get(privateKey))).when(mockSecurityService).getKeyPair(any(), any());
        res = fs.get("arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh",
                CURRENT_LABEL);
        assertEquals("arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh",res.getArn());
        response = clientV2.getSecretValue(secretExists);
        // secret is loaded into cache
        assertEquals("secretValue", response.getSecretValue().getSecretString());
    }

    @Test
    void GIVEN_secret_service_And_device_config_changes_throw_ex_When_ipc_handler_with_refresh_called_THEN_return_from_cache(ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, SecretCryptoException.class);
        ignoreExceptionOfType(context, GetSecretException.class);
        startKernelWithConfig("config.yaml", State.RUNNING, CONFIG_CLOUD_CALLS);
        lenient().doThrow(KeyLoadingException.class).when(mockSecurityService).getKeyPair(any(),
                any());
        kernel.getConfig().lookup(SYSTEM_NAMESPACE_KEY, DEVICE_PARAM_PRIVATE_KEY_PATH).withValue("someKey.pem");
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest secretExists =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        secretExists.setSecretId("Secret1");
        secretExists.setVersionId(null);
        secretExists.setRefresh(true);
        GreengrassCoreIPCClientV2 clientV2 = IPCTestUtils.connectV2Client(kernel, "ComponentRequestingSecrets");
        GetSecretValueResponse response= clientV2.getSecretValue(secretExists);
        assertEquals("arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh", response.getSecretId());
        assertEquals(VERSION_ID, response.getVersionId());
        assertTrue(response.getVersionStage().contains(CURRENT_LABEL));
        assertEquals("secretValue", response.getSecretValue().getSecretString());
    }

    @Test
    void GIVEN_secret_service_WHEN_ipc_handler_called_THEN_correct_response_returned() throws Exception {
        startKernelWithConfig("config.yaml", State.RUNNING, CONFIG_CLOUD_CALLS);
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest secretExists =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        secretExists.setSecretId("Secret1");
        secretExists.setVersionId(VERSION_ID);

        GreengrassCoreIPCClientV2 clientV2 = IPCTestUtils.connectV2Client(kernel, "ComponentRequestingSecrets");
        GetSecretValueResponse response= clientV2.getSecretValue(secretExists);
        assertEquals("arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh", response.getSecretId());
        assertEquals(VERSION_ID, response.getVersionId());
        assertTrue(response.getVersionStage().contains(CURRENT_LABEL));
        assertEquals("secretValue", response.getSecretValue().getSecretString());
    }

    @Test
    void GIVEN_secret_service_WHEN_ipc_request_partialarn_THEN_correct_response_returned() throws Exception {
        startKernelWithConfig("config.yaml", State.RUNNING, CONFIG_CLOUD_CALLS);
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest secretWithPartialArn =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        secretWithPartialArn.setSecretId("partialarn");


        awaitSecretResolvable("partialarn");
        GreengrassCoreIPCClientV2 clientV2 = IPCTestUtils.connectV2Client(kernel, "ComponentRequestingSecrets");
        GetSecretValueResponse response = clientV2.getSecretValue(secretWithPartialArn);
        assertEquals("arn:aws:secretsmanager:us-east-1:999936977227:secret:partialarn-43lYMk", response.getSecretId());
        assertEquals("partialarnid", response.getVersionId());
        assertTrue(response.getVersionStage().contains(CURRENT_LABEL));
        assertEquals("secretValue", response.getSecretValue().getSecretString());
    }

    @Test
    void GIVEN_secret_service_WHEN_periodic_refresh_THEN_secret_updated() throws Exception {
        startKernelWithConfig("config_refresh.yaml", State.RUNNING, REFRESH_CONFIG_CLOUD_CALLS);
        String arn = "arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh";

        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest secretExists =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        secretExists.setSecretId("Secret1");
        secretExists.setVersionStage(CURRENT_LABEL);

        GreengrassCoreIPCClientV2 clientV2 = IPCTestUtils.connectV2Client(kernel, "ComponentRequestingSecrets");
        GetSecretValueResponse response= clientV2.getSecretValue(secretExists);
        assertEquals(arn, response.getSecretId());
        assertEquals(VERSION_ID, response.getVersionId());
        assertTrue(response.getVersionStage().contains(CURRENT_LABEL));
        assertEquals("secretValue", response.getSecretValue().getSecretString());

        // Point the cloud at a new version, to be picked up by the next periodic refresh. Swapping the reference is
        // safe while a sync is in flight; re-stubbing the mock here is not, because the background call races it.
        currentLabelResponse.set(software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse.builder()
                .name("Secret1").arn(arn).secretString("updatedSecretValue").versionId("updatedVersionId")
                .versionStages(CURRENT_LABEL).createdDate(Instant.now().minusSeconds(1000000)).build());

        // Periodic refresh runs every 3 seconds as per the config
        GetSecretValueResponse refreshed = awaitVersionId(clientV2, secretExists, "updatedVersionId", 30);
        assertEquals(arn, refreshed.getSecretId());
        assertTrue(refreshed.getVersionStage().contains(CURRENT_LABEL));
        assertEquals("updatedSecretValue", refreshed.getSecretValue().getSecretString());
    }

    /**
     * Read the secret until it reports expectedVersionId, up to timeoutSeconds. Used where the update arrives on a
     * background refresh, so the test cannot know exactly when the cache changes.
     */
    private GetSecretValueResponse awaitVersionId(GreengrassCoreIPCClientV2 clientV2,
            software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest request, String expectedVersionId,
            long timeoutSeconds) throws Exception {
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(timeoutSeconds);
        GetSecretValueResponse response = clientV2.getSecretValue(request);
        while (!expectedVersionId.equals(response.getVersionId()) && System.currentTimeMillis() < deadline) {
            Thread.sleep(200);
            response = clientV2.getSecretValue(request);
        }
        assertEquals(expectedVersionId, response.getVersionId(), "secret was not refreshed within "
                + timeoutSeconds + "s");
        return response;
    }

    @Test
    void GIVEN_secret_service_WHEN_ipc_request_with_refresh_THEN_fetch_from_cloud() throws Exception {
        startKernelWithConfig("config.yaml", State.RUNNING, CONFIG_CLOUD_CALLS);
        String arn = "arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh";
        // New secret exists on cloud.
        lenient().doReturn(software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse.builder()
                        .name("Secret1").arn(arn).secretString("updatedSecretValue").versionId("updatedVersionId")
                        .versionStages("new").createdDate(Instant.now().minusSeconds(1000000)).build())
                .when(secretClient).getSecret(GetSecretValueRequest.builder().secretId(arn).versionStage("new").build());

        GreengrassCoreIPCClientV2 clientV2 = IPCTestUtils.connectV2Client(kernel, "ComponentRequestingSecrets");
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest getSecret =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        getSecret.setSecretId("Secret1");
        getSecret.setVersionStage("new");
        // IPC request without refresh
        GetSecretValueResponse response= clientV2.getSecretValue(getSecret);
        assertEquals(arn, response.getSecretId());
        assertEquals("id2", response.getVersionId());
        assertEquals("secretValue2", response.getSecretValue().getSecretString());

        // IPC request with refresh
        getSecret.setRefresh(true);
        GetSecretValueResponse response2= clientV2.getSecretValue(getSecret);
        assertEquals(arn, response2.getSecretId());
        assertEquals("updatedVersionId", response2.getVersionId());
        assertEquals("updatedSecretValue", response2.getSecretValue().getSecretString());
    }

    @Test
    void GIVEN_secret_service_with_invalid_cloud_queue_size_WHEN_ipc_request_THEN_use_default_size() throws Exception {
        LogConfig.getRootLogConfig().setLevel(Level.DEBUG);
        startKernelWithConfig("config.yaml", State.RUNNING, CONFIG_CLOUD_CALLS);
        String arn = "arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh";
        int noOfCloudCalls = 130;
        kernel.getConfig().lookupTopics("services", SecretManagerService.SECRET_MANAGER_SERVICE_NAME,
                CONFIGURATION_CONFIG_KEY, PERFORMANCE_TOPIC).lookup(CLOUD_REQUEST_QUEUE_SIZE_TOPIC).withValue(0);
        CountDownLatch responseLatch = new CountDownLatch(noOfCloudCalls);
        lenient().doAnswer((i)-> {
            responseLatch.countDown();
            return software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse.builder()
                            .name("Secret1").arn(arn).secretString("updatedSecretValue").versionId("updatedVersionId")
                            .versionStages("new").createdDate(Instant.now().minusSeconds(1000000)).build();
                })
                .when(secretClient).getSecret(GetSecretValueRequest.builder().secretId(arn).versionStage("new").build());

        GreengrassCoreIPCClientV2 clientV2 = null;
        try {
            clientV2 = IPCTestUtils.connectV2Client(kernel, "ComponentRequestingSecrets");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        CountDownLatch latch = new CountDownLatch(noOfCloudCalls);
        for (int i=0;i<=noOfCloudCalls;i++) {
            GreengrassCoreIPCClientV2 finalClientV = clientV2;
            CompletableFuture.supplyAsync(()->{
                software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest getSecret =
                        new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
                getSecret.setSecretId("Secret1");
                getSecret.setVersionStage("new");
                getSecret.setRefresh(true);
                GetSecretValueResponse response= null;
                try {

                    response = finalClientV.getSecretValue(getSecret);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                } catch (ServiceError err) {
                    assertEquals("Unable to queue request",err.getMessage());
                }
                latch.countDown();
                assertEquals(arn, response.getSecretId());
                assertEquals("id2", response.getVersionId());
                assertEquals("secretValue2", response.getSecretValue().getSecretString());
                return null;
            });
        }
        latch.await(3, TimeUnit.MINUTES);
        // At least 100 (default cloud call queue size) tasks are completed.Some tasks are rejected.
        assertTrue(responseLatch.getCount()>0 && responseLatch.getCount()<=30);
    }

    @Test
    void GIVEN_secret_service_WHEN_ipc_request_with_refresh_fails_THEN_fetch_from_cache(ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, SecretManagerException.class);
        startKernelWithConfig("config.yaml", State.RUNNING, CONFIG_CLOUD_CALLS);
        String arn = "arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh";
        // New secret exists on cloud.
        lenient().doThrow(SecretManagerException.class).when(secretClient).getSecret(GetSecretValueRequest.builder().secretId(arn).versionStage(
                "new").build());

        GreengrassCoreIPCClientV2 clientV2 = IPCTestUtils.connectV2Client(kernel, "ComponentRequestingSecrets");
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest getSecret =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        getSecret.setSecretId("Secret1");
        getSecret.setVersionStage("new");
        // IPC request without refresh
        GetSecretValueResponse response= clientV2.getSecretValue(getSecret);
        assertEquals(arn, response.getSecretId());
        assertEquals("id2", response.getVersionId());
        assertEquals("secretValue2", response.getSecretValue().getSecretString());

        // IPC request with refresh
        getSecret.setRefresh(true);
        GetSecretValueResponse response2= clientV2.getSecretValue(getSecret);
        assertEquals(arn, response2.getSecretId());
        assertEquals("id2", response2.getVersionId());
        assertEquals("secretValue2", response2.getSecretValue().getSecretString());
    }

    @Test
    void GIVEN_secret_service_WHEN_ipc_request_unauthorized_THEN_throws_unauthorized_exception() throws Exception {
        startKernelWithConfig("config.yaml", State.RUNNING, CONFIG_CLOUD_CALLS);
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest req =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        req.setSecretId("Secret1");
        req.setVersionId(VERSION_ID);

        GreengrassCoreIPCClientV2 clientV2 = IPCTestUtils.connectV2Client(kernel, "ComponentWithNoAccessPolicy");
        assertThrows(UnauthorizedError.class, () -> clientV2.getSecretValue(req));
    }

    @Test
    void GIVEN_secret_service_WHEN_ipc_request_get_secret_not_exists_THEN_throw_error(ExtensionContext context)
            throws Exception {
        ignoreExceptionOfType(context, GetSecretException.class);
        startKernelWithConfig("config.yaml", State.RUNNING, CONFIG_CLOUD_CALLS);
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest secretNotConfiguredReq =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        secretNotConfiguredReq.setSecretId("secretNotConfigured");
        secretNotConfiguredReq.setVersionId(VERSION_ID);

        GreengrassCoreIPCClientV2 clientV2 = IPCTestUtils.connectV2Client(kernel, "ComponentRequestingSecrets");
        ResourceNotFoundError err = assertThrows(ResourceNotFoundError.class,
                () -> clientV2.getSecretValue(secretNotConfiguredReq));
        assertThat(err.getMessage(), containsString("Secret not configured secretNotConfigured"));
    }

    @Test
    void GIVEN_secret_service_WHEN_cloud_sync_is_slow_THEN_service_reaches_running_without_waiting(
            ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, SecretManagerException.class);
        URI privateKey = getClass().getResource("privateKey.pem").toURI();
        URI certUri = getClass().getResource("cert.pem").toURI();
        lenient().doReturn(privateKey).when(mockSecurityService).getDeviceIdentityPrivateKeyURI();
        lenient().doReturn(certUri).when(mockSecurityService).getDeviceIdentityCertificateURI();
        lenient().doReturn(EncryptionUtils.loadPrivateKeyPair(Paths.get(privateKey)))
                .when(mockSecurityService).getKeyPair(privateKey, certUri);

        String arn = "arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh";
        CountDownLatch syncStarted = new CountDownLatch(1);
        CountDownLatch allowSyncToFinish = new CountDownLatch(1);
        AtomicBoolean cloudSyncFinished = new AtomicBoolean(false);

        // Cloud sync will block until we release it
        lenient().doAnswer(invocation -> {
            syncStarted.countDown();
            try {
                allowSyncToFinish.await();
            } catch (InterruptedException e) {
                // Kernel shutdown interrupts threads; this is expected during teardown
                Thread.currentThread().interrupt();
                throw new SecretManagerException("Interrupted during sync");
            }
            cloudSyncFinished.set(true);
            return software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse.builder()
                    .name("Secret1").arn(arn).secretString("secretValue").versionId(VERSION_ID)
                    .versionStages(CURRENT_LABEL)
                    .createdDate(Instant.now().minusSeconds(1000000)).build();
        }).when(secretClient).getSecret(any(GetSecretValueRequest.class));

        kernel = new Kernel();
        kernel.parseArgs("-r", rootDir.toAbsolutePath().toString(), "-i",
                getClass().getResource("config_refresh.yaml").toString());

        CountDownLatch secretManagerRunning = new CountDownLatch(1);
        kernel.getContext().addGlobalStateChangeListener((GreengrassService service, State was, State newState) -> {
            if (service.getName().equals(SecretManagerService.SECRET_MANAGER_SERVICE_NAME)
                    && newState.equals(State.RUNNING)) {
                secretManagerRunning.countDown();
            }
        });
        kernel.getContext().put(AWSSecretClient.class, secretClient);
        kernel.getContext().put(SecurityService.class, mockSecurityService);
        kernel.launch();

        // Wait for sync to start (proves the scheduled task is running)
        assertTrue(syncStarted.await(10, TimeUnit.SECONDS), "Cloud sync should have started");
        // Service should reach RUNNING while cloud sync is still blocked
        assertTrue(secretManagerRunning.await(10, TimeUnit.SECONDS) && !cloudSyncFinished.get(),
                "Service should reach RUNNING without waiting for cloud sync");
        allowSyncToFinish.countDown();
    }
}
