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
import com.aws.greengrass.util.Coerce;
import com.aws.greengrass.util.EncryptionUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static com.aws.greengrass.componentmanager.KernelConfigResolver.CONFIGURATION_CONFIG_KEY;
import static com.aws.greengrass.deployment.DeviceConfiguration.DEVICE_PARAM_PRIVATE_KEY_PATH;
import static com.aws.greengrass.deployment.DeviceConfiguration.SYSTEM_NAMESPACE_KEY;
import static com.aws.greengrass.secretmanager.SecretManagerService.CLOUD_REQUEST_QUEUE_SIZE_TOPIC;
import static com.aws.greengrass.secretmanager.SecretManagerService.PERFORMANCE_TOPIC;
import static com.aws.greengrass.secretmanager.SecretManagerService.PERIODIC_REFRESH_INTERVAL_MIN;
import static com.aws.greengrass.secretmanager.TestUtil.ignoreErrors;
import static com.aws.greengrass.testcommons.testutilities.ExceptionLogProtector.ignoreExceptionOfType;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith({MockitoExtension.class, GGExtension.class})
public class SecretManagerServiceIntegTest extends BaseITCase {
    private final String VERSION_ID = "id";
    private final String CURRENT_LABEL = "AWSCURRENT";
    private Kernel kernel;
    private final SecurityService mockSecurityService = spy(new SecurityService(mock(DeviceConfiguration.class)));

    @TempDir
    Path rootDir;

    @Mock
    AWSSecretClient secretClient;

    /**
     * Starts the kernel with the default cloud responses and, for a one-time refresh config, waits for the background
     * cloud sync to finish so tests see the downloaded secrets.
     */
    void startKernelWithConfig(String configFile, State expectedState) throws Exception {
        mockSecretResponse();
        launchKernel(configFile, expectedState);
        if (isOneTimeRefresh()) {
            awaitOneTimeCloudSync();
        }
    }

    /**
     * Starts the kernel and waits for the secret manager to reach the expected state. It does not wait for the cloud
     * sync, which runs in the background.
     */
    private void launchKernel(String configFile, State expectedState) throws Exception {
        URI privateKey = getClass().getResource("privateKey.pem").toURI();
        URI certUri = getClass().getResource("cert.pem").toURI();
        lenient().doReturn(privateKey).when(mockSecurityService).getDeviceIdentityPrivateKeyURI();
        lenient().doReturn(certUri).when(mockSecurityService).getDeviceIdentityCertificateURI();
        lenient().doReturn(EncryptionUtils.loadPrivateKeyPair(Paths.get(privateKey))).when(mockSecurityService).getKeyPair(privateKey, certUri);
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
    }

    private boolean isOneTimeRefresh() {
        return Coerce.toDouble(kernel.getConfig()
                .lookupTopics("services", SecretManagerService.SECRET_MANAGER_SERVICE_NAME, CONFIGURATION_CONFIG_KEY)
                .findOrDefault(0, PERIODIC_REFRESH_INTERVAL_MIN)) <= 0;
    }

    // Waits for the most recently scheduled one-time sync. Must not be used with periodic refresh, whose future
    // never completes.
    private void awaitOneTimeCloudSync() throws Exception {
        kernel.getContext().get(SecretManagerService.class).getScheduledSyncFuture().get(10, TimeUnit.SECONDS);
    }

    private void mockSecretResponse() throws SecretManagerException, IOException {
        String secretArn = "arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh";
        String secretName = "Secret1";
        lenient().doReturn(software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse.builder()
                .name(secretName).arn(secretArn).secretString("secretValue").versionId(VERSION_ID)
                .versionStages(CURRENT_LABEL)
                .createdDate(Instant.now().minusSeconds(1000000)).build())
                .when(secretClient).getSecret(GetSecretValueRequest.builder().secretId(secretArn).versionStage(CURRENT_LABEL).build());

        lenient().doReturn(software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse.builder()
                .name(secretName).arn(secretArn).secretString("secretValue2").versionId("id2")
                .versionStages("new").createdDate(Instant.now().minusSeconds(1000000)).build())
                .when(secretClient).getSecret(GetSecretValueRequest.builder().secretId(secretArn).versionStage("new").build());

        lenient().doReturn(
                software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse.builder().name("partialarn")
                        .arn("arn:aws:secretsmanager:us-east-1:999936977227:secret:partialarn" + "-43lYMk")
                        .secretString("secretValue").versionId("partialarnid").versionStages(CURRENT_LABEL)
                        .createdDate(Instant.now().minusSeconds(1000000)).build()).when(secretClient).getSecret(
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
        startKernelWithConfig("config.yaml", State.RUNNING);
        final String serviceName = "ComponentRequestingSecrets";

        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest req =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        req.setSecretId("");
        req.setVersionId(VERSION_ID);
        GreengrassCoreIPCClientV2 clientV2 = IPCTestUtils.connectV2Client(kernel, serviceName);
        assertThrows(ServiceError.class, () -> clientV2.getSecretValue(req));
        ServiceError e = assertThrows(ServiceError.class, () -> clientV2.getSecretValue(req));
        assertThat(e.getMessage(), containsString("SecretId absent in the request"));
    }


    @Test
    void GIVEN_secret_service_And_device_config_changes_throw_ex_When_ipc_handler_called_THEN_return_from_cache() throws Exception {
        startKernelWithConfig("config.yaml", State.RUNNING);
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
        startKernelWithConfig("config.yaml", State.RUNNING);
        ignoreExceptionOfType(context, SecretCryptoException.class);
        ignoreExceptionOfType(context, GetSecretException.class);
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
        SecretManager secretManager = kernel.getContext().get(SecretManager.class);
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

        // Force a cache reload while the crypter is broken. reloadCache() clears the in-memory cache and then
        // attempts to reload from the local store, but every secret fails to decrypt and is skipped (logged and
        // swallowed), so it returns normally with an empty cache. This exercises the cold-cache path directly
        // (startup() no longer reloads the cache, so a service restart would not clear it).
        secretManager.reloadCache();

        // Then secrets still exist on disk
        FileSecretStore fs = kernel.getContext().get(FileSecretStore.class);
        AWSSecretResponse res = fs.get("arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh",
                CURRENT_LABEL);
        assertEquals("arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh",res.getArn());
        // The secret is not present in cache because it could not be decrypted during reload
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
        startKernelWithConfig("config.yaml", State.RUNNING);
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
        startKernelWithConfig("config.yaml", State.RUNNING);
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
        startKernelWithConfig("config.yaml", State.RUNNING);
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest secretWithPartialArn =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        secretWithPartialArn.setSecretId("partialarn");


        GreengrassCoreIPCClientV2 clientV2 = IPCTestUtils.connectV2Client(kernel, "ComponentRequestingSecrets");
        GetSecretValueResponse response = clientV2.getSecretValue(secretWithPartialArn);
        assertEquals("arn:aws:secretsmanager:us-east-1:999936977227:secret:partialarn-43lYMk", response.getSecretId());
        assertEquals("partialarnid", response.getVersionId());
        assertTrue(response.getVersionStage().contains(CURRENT_LABEL));
        assertEquals("secretValue", response.getSecretValue().getSecretString());
    }

    @Test
    void GIVEN_secret_service_WHEN_periodic_refresh_THEN_secret_updated() throws Exception {
        startKernelWithConfig("config_refresh.yaml", State.RUNNING);
        String arn = "arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh";

        // Set up updated response that periodic refresh will pick up
        lenient().doReturn(software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse.builder()
                        .name("Secret1").arn(arn).secretString("updatedSecretValue").versionId("updatedVersionId")
                        .versionStages(CURRENT_LABEL).createdDate(Instant.now().minusSeconds(1000000)).build())
                .when(secretClient).getSecret(GetSecretValueRequest.builder().secretId(arn).versionStage(CURRENT_LABEL).build());

        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest secretExists =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        secretExists.setSecretId("Secret1");
        secretExists.setVersionStage(CURRENT_LABEL);

        // Wait for periodic refresh to pick up the updated value (config_refresh.yaml uses a 3 second interval).
        // Poll instead of sleeping a fixed duration so the test is not timing-fragile: the cache serves the old
        // version until the background refresh replaces it.
        GreengrassCoreIPCClientV2 clientV2 = IPCTestUtils.connectV2Client(kernel, "ComponentRequestingSecrets");
        GetSecretValueResponse response = null;
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(20);
        while (System.currentTimeMillis() < deadline) {
            response = clientV2.getSecretValue(secretExists);
            if ("updatedVersionId".equals(response.getVersionId())) {
                break;
            }
            Thread.sleep(500);
        }
        assertEquals(arn, response.getSecretId());
        assertEquals("updatedVersionId", response.getVersionId());
        assertTrue(response.getVersionStage().contains(CURRENT_LABEL));
        assertEquals("updatedSecretValue", response.getSecretValue().getSecretString());
    }

    @Test
    void GIVEN_secret_service_WHEN_ipc_request_with_refresh_THEN_fetch_from_cloud() throws Exception {
        startKernelWithConfig("config.yaml", State.RUNNING);
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
        startKernelWithConfig("config.yaml", State.RUNNING);
        String arn = "arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh";
        int noOfCloudCalls = 130;
        kernel.getConfig().lookupTopics("services", SecretManagerService.SECRET_MANAGER_SERVICE_NAME,
                CONFIGURATION_CONFIG_KEY, PERFORMANCE_TOPIC).lookup(CLOUD_REQUEST_QUEUE_SIZE_TOPIC).withValue(0);
        lenient().doAnswer((i) ->
                software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse.builder()
                        .name("Secret1").arn(arn).secretString("updatedSecretValue").versionId("updatedVersionId")
                        .versionStages("new").createdDate(Instant.now().minusSeconds(1000000)).build())
                .when(secretClient).getSecret(GetSecretValueRequest.builder().secretId(arn).versionStage("new").build());

        GreengrassCoreIPCClientV2 clientV2 = IPCTestUtils.connectV2Client(kernel, "ComponentRequestingSecrets");

        // Fire the requests concurrently and observe every outcome deterministically: a request either succeeds
        // (served from cache) or is rejected with "Unable to queue request" once the queue is full. Join every future
        // so no outcome is silently swallowed on a pool thread.
        AtomicInteger succeeded = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        CompletableFuture<?>[] futures = new CompletableFuture[noOfCloudCalls];
        for (int i = 0; i < noOfCloudCalls; i++) {
            GreengrassCoreIPCClientV2 finalClientV = clientV2;
            futures[i] = CompletableFuture.runAsync(() -> {
                software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest getSecret =
                        new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
                getSecret.setSecretId("Secret1");
                getSecret.setVersionStage("new");
                getSecret.setRefresh(true);
                try {
                    GetSecretValueResponse response = finalClientV.getSecretValue(getSecret);
                    assertEquals(arn, response.getSecretId());
                    assertEquals("updatedVersionId", response.getVersionId());
                    assertEquals("updatedSecretValue", response.getSecretValue().getSecretString());
                    succeeded.incrementAndGet();
                } catch (ServiceError err) {
                    assertEquals("Unable to queue request", err.getMessage());
                    rejected.incrementAndGet();
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            });
        }
        CompletableFuture.allOf(futures).get(3, TimeUnit.MINUTES);

        // Every request is accounted for, the queue backed by the default size (100) rejected the overflow (so not
        // all requests succeeded), and at least one request got through. This verifies the invalid size (0) fell back
        // to the default without asserting an exact, timing-dependent reject count.
        assertEquals(noOfCloudCalls, succeeded.get() + rejected.get());
        assertTrue(rejected.get() > 0, "expected some requests to be rejected by the default-sized queue");
        assertTrue(succeeded.get() > 0, "expected some requests to succeed");
    }

    @Test
    void GIVEN_secret_service_WHEN_ipc_request_with_refresh_fails_THEN_fetch_from_cache(ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, SecretManagerException.class);
        startKernelWithConfig("config.yaml", State.RUNNING);
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
        assertEquals("id2", response.getVersionId());
        assertEquals("secretValue2", response.getSecretValue().getSecretString());
    }

    @Test
    void GIVEN_secret_service_WHEN_ipc_request_unauthorized_THEN_throws_unauthorized_exception() throws Exception {
        startKernelWithConfig("config.yaml", State.RUNNING);
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
        startKernelWithConfig("config.yaml", State.RUNNING);
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest secretNotConfiguredReq =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        secretNotConfiguredReq.setSecretId("secretNotConfigured");
        secretNotConfiguredReq.setVersionId(VERSION_ID);

        GreengrassCoreIPCClientV2 clientV2 = IPCTestUtils.connectV2Client(kernel, "ComponentRequestingSecrets");
        ResourceNotFoundError err = assertThrows(ResourceNotFoundError.class,
                () -> clientV2.getSecretValue(secretNotConfiguredReq));
        assertThat(err.getMessage(), containsString("Secret not configured secretNotConfigured"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"config.yaml", "config_refresh.yaml"}) // one-time and periodic refresh
    void GIVEN_secret_service_WHEN_cloud_sync_is_slow_THEN_service_reaches_running_without_waiting(String configFile,
            ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, SecretManagerException.class);
        String arn = "arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh";
        CountDownLatch cloudDownloadReleased = new CountDownLatch(1);
        AtomicBoolean cloudDownloadFinished = new AtomicBoolean(false);

        // Cloud download blocks until the test releases it
        doAnswer(invocation -> {
            try {
                cloudDownloadReleased.await();
            } catch (InterruptedException e) {
                // Kernel shutdown interrupts the sync; this is expected during teardown
                Thread.currentThread().interrupt();
                throw new SecretManagerException("Interrupted during sync");
            }
            cloudDownloadFinished.set(true);
            return software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse.builder()
                    .name("Secret1").arn(arn).secretString("secretValue").versionId(VERSION_ID)
                    .versionStages(CURRENT_LABEL)
                    .createdDate(Instant.now().minusSeconds(1000000)).build();
        }).when(secretClient).getSecret(any(GetSecretValueRequest.class));

        try {
            launchKernel(configFile, State.RUNNING);
            assertFalse(cloudDownloadFinished.get(), "Service should reach RUNNING without waiting for cloud sync");
        } finally {
            cloudDownloadReleased.countDown();
        }
    }

    @Test
    void GIVEN_secret_service_WHEN_cloud_sync_slow_THEN_secrets_available_after_sync_completes(
            ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, SecretManagerException.class);
        ignoreExceptionOfType(context, GetSecretException.class);
        String arn = "arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh";
        CountDownLatch syncAttempted = new CountDownLatch(1);

        // Cloud sync fails initially (simulating slow/unavailable network)
        doAnswer(invocation -> {
            syncAttempted.countDown();
            throw new SecretManagerException("Network unavailable");
        }).when(secretClient).getSecret(any(GetSecretValueRequest.class));

        // Service is running but secrets haven't synced
        launchKernel("config_refresh.yaml", State.RUNNING);
        assertTrue(syncAttempted.await(10, TimeUnit.SECONDS));

        GreengrassCoreIPCClientV2 clientV2 = IPCTestUtils.connectV2Client(kernel, "ComponentRequestingSecrets");
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest req =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        req.setSecretId("Secret1");
        req.setVersionStage(CURRENT_LABEL);

        // Secret not available because sync failed
        assertThrows(ResourceNotFoundError.class, () -> clientV2.getSecretValue(req));

        // Now make cloud sync succeed on next periodic refresh
        lenient().doReturn(software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse.builder()
                .name("Secret1").arn(arn).secretString("secretValue").versionId(VERSION_ID)
                .versionStages(CURRENT_LABEL)
                .createdDate(Instant.now().minusSeconds(1000000)).build())
                .when(secretClient).getSecret(any(GetSecretValueRequest.class));

        // Wait for a periodic refresh to pick up the secret (config_refresh.yaml uses a 3 second
        // interval). Poll instead of sleeping a fixed duration so the test is not timing-fragile:
        // getSecretValue throws ResourceNotFoundError until the background sync populates the cache.
        GetSecretValueResponse response = null;
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(20);
        while (System.currentTimeMillis() < deadline) {
            try {
                response = clientV2.getSecretValue(req);
                break;
            } catch (ResourceNotFoundError e) {
                Thread.sleep(500);
            }
        }

        // Secret should now be available
        assertNotNull(response, "Secret should become available after a successful periodic refresh");
        assertEquals(arn, response.getSecretId());
        assertEquals(VERSION_ID, response.getVersionId());
        assertEquals("secretValue", response.getSecretValue().getSecretString());
    }

    @Test
    void GIVEN_secret_service_WHEN_restarted_without_reinstall_THEN_serves_from_surviving_in_memory_cache(
            ExtensionContext context) throws Exception {
        startKernelWithConfig("config.yaml", State.RUNNING);
        ignoreExceptionOfType(context, SecretCryptoException.class);
        ignoreExceptionOfType(context, GetSecretException.class);
        ignoreExceptionOfType(context, SecretManagerException.class);

        // Verify secret is available after initial startup (decrypted into the in-memory cache)
        GreengrassCoreIPCClientV2 clientV2 = IPCTestUtils.connectV2Client(kernel, "ComponentRequestingSecrets");
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest req =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        req.setSecretId("Secret1");
        req.setVersionStage(CURRENT_LABEL);
        GetSecretValueResponse response = clientV2.getSecretValue(req);
        assertEquals("secretValue", response.getSecretValue().getSecretString());

        // Break the crypter so any reload from the local disk store can no longer decrypt. With decryption
        // impossible, a disk reload would yield an empty cache, so if the secret is still served after the restart
        // it can only have come from the in-memory cache that survived the restart (not a fresh disk reload, and not
        // the cloud). Fail keypair loading with a non-retryable exception (ServiceUnavailableException would take
        // 5 minutes), then change config so the crypter is reloaded into a broken state.
        lenient().doThrow(KeyLoadingException.class).when(mockSecurityService).getKeyPair(any(), any());
        kernel.getConfig().lookup(SYSTEM_NAMESPACE_KEY, DEVICE_PARAM_PRIVATE_KEY_PATH).withValue("someKey.pem");
        kernel.getContext().runOnPublishQueueAndWait(() -> { });
        LocalStoreMap map = kernel.getContext().get(LocalStoreMap.class);
        assertThrows(SecretCryptoException.class, () -> map.getCrypter());

        // Also make cloud unavailable so a served value cannot come from a cloud fetch either.
        lenient().doThrow(new SecretManagerException("Network unavailable"))
                .when(secretClient).getSecret(any(GetSecretValueRequest.class));

        // Restart the service (INSTALLED -> RUNNING, install() is not re-run). startup() no longer reloads the
        // cache, so the already-decrypted in-memory entries survive. Under the previous design startup() ran
        // reloadCache(), which cleared the cache and could not repopulate it with a broken crypter, so the secret
        // would have been lost after restart. This test asserts the new behavior: the cache survives.
        SecretManagerService service = kernel.getContext().get(SecretManagerService.class);
        CountDownLatch secretManagerRunning = new CountDownLatch(1);
        kernel.getContext().addGlobalStateChangeListener((GreengrassService svc, State was, State newState) -> {
            if (svc.getName().equals(SecretManagerService.SECRET_MANAGER_SERVICE_NAME)
                    && newState.equals(State.RUNNING) && was.equals(State.STARTING)) {
                secretManagerRunning.countDown();
            }
        });
        service.requestRestart();
        assertTrue(secretManagerRunning.await(10, TimeUnit.SECONDS));

        // Secret is still served, and since neither decrypt (crypter broken) nor cloud (unavailable) can produce it,
        // it must have come from the surviving in-memory cache.
        GetSecretValueResponse responseAfterRestart = clientV2.getSecretValue(req);
        assertEquals("secretValue", responseAfterRestart.getSecretValue().getSecretString());
    }

    @Test
    void GIVEN_secret_service_WHEN_config_change_syncs_then_restarted_THEN_synced_value_preserved()
            throws Exception {
        startKernelWithConfig("config.yaml", State.RUNNING);

        // Verify initial secret is available
        GreengrassCoreIPCClientV2 clientV2 = IPCTestUtils.connectV2Client(kernel, "ComponentRequestingSecrets");
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest req =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        req.setSecretId("Secret1");
        req.setVersionStage(CURRENT_LABEL);
        GetSecretValueResponse response = clientV2.getSecretValue(req);
        assertEquals("secretValue", response.getSecretValue().getSecretString());

        // Update the cloud secret mock to return new values
        String arn = "arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh";
        org.mockito.Mockito.reset(secretClient);
        lenient().doReturn(software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse.builder()
                        .name("Secret1").arn(arn).secretString("updatedAfterConfigChange").versionId("newVersionId")
                        .versionStages(CURRENT_LABEL)
                        .createdDate(Instant.now().minusSeconds(1000000)).build())
                .when(secretClient).getSecret(any(GetSecretValueRequest.class));

        // Trigger serviceChanged by changing periodicRefreshIntervalMin. Since the value is 0,
        // serviceChanged runs the cloud sync once in the background, which refreshes the in-memory
        // cache (and local store) with the updated cloud value.
        kernel.getConfig().lookupTopics("services", SecretManagerService.SECRET_MANAGER_SERVICE_NAME,
                CONFIGURATION_CONFIG_KEY).lookup("periodicRefreshIntervalMin")
                .withNewerValue(System.currentTimeMillis(), 0);
        // Wait for publish queue to process the config change
        kernel.getContext().runOnPublishQueueAndWait(() -> {});

        awaitOneTimeCloudSync();

        // Now restart the service (INSTALLED -> RUNNING, install() is not re-run). startup() does not reload the
        // cache, so the fresh in-memory value synced above is preserved and served after the restart.
        CountDownLatch secretManagerRunning = new CountDownLatch(1);
        kernel.getContext().addGlobalStateChangeListener((GreengrassService svc, State was, State newState) -> {
            if (svc.getName().equals(SecretManagerService.SECRET_MANAGER_SERVICE_NAME)
                    && newState.equals(State.RUNNING) && was.equals(State.STARTING)) {
                secretManagerRunning.countDown();
            }
        });
        SecretManagerService service = kernel.getContext().get(SecretManagerService.class);
        service.requestRestart();
        assertTrue(secretManagerRunning.await(10, TimeUnit.SECONDS));

        // The updated cloud value should be available after the restart
        GetSecretValueResponse responseAfterRestart = clientV2.getSecretValue(req);
        assertEquals("updatedAfterConfigChange", responseAfterRestart.getSecretValue().getSecretString());
        assertEquals("newVersionId", responseAfterRestart.getVersionId());
    }
}
