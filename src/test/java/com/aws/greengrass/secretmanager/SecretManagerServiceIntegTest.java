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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.spy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

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

    void startKernelWithConfig(String configFile, State expectedState) throws Exception {
        URI privateKey = getClass().getResource("privateKey.pem").toURI();
        URI certUri = getClass().getResource("cert.pem").toURI();
        lenient().doReturn(privateKey).when(mockSecurityService).getDeviceIdentityPrivateKeyURI();
        lenient().doReturn(certUri).when(mockSecurityService).getDeviceIdentityCertificateURI();
        lenient().doReturn(EncryptionUtils.loadPrivateKeyPair(Paths.get(privateKey))).when(mockSecurityService).getKeyPair(privateKey, certUri);
        mockSecretResponse();
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

        // Wait for periodic refresh to pick up the updated value (interval is 3 seconds)
        GreengrassCoreIPCClientV2 clientV2 = IPCTestUtils.connectV2Client(kernel, "ComponentRequestingSecrets");
        Thread.sleep(5000);
        GetSecretValueResponse response = clientV2.getSecretValue(secretExists);
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

        // Cloud sync will block until we release it
        lenient().doAnswer(invocation -> {
            syncStarted.countDown();
            try {
                allowSyncToFinish.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                // Kernel shutdown interrupts threads; this is expected during teardown
                Thread.currentThread().interrupt();
                throw new SecretManagerException("Interrupted during sync");
            }
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
        assertTrue(syncStarted.await(10, TimeUnit.SECONDS),
                "Cloud sync should have started");
        // Service should reach RUNNING while cloud sync is still blocked
        assertTrue(secretManagerRunning.await(10, TimeUnit.SECONDS),
                "Service should reach RUNNING without waiting for cloud sync");
        // Verify sync is still in progress (hasn't completed yet)
        assertEquals(1, allowSyncToFinish.getCount(),
                "Cloud sync should still be blocked when service reaches RUNNING");

        // Release the sync so teardown can complete cleanly
        allowSyncToFinish.countDown();
    }

    @Test
    void GIVEN_secret_service_WHEN_cloud_sync_fails_THEN_service_still_reaches_running(ExtensionContext context)
            throws Exception {
        ignoreExceptionOfType(context, SecretManagerException.class);
        ignoreExceptionOfType(context, RuntimeException.class);

        URI privateKey = getClass().getResource("privateKey.pem").toURI();
        URI certUri = getClass().getResource("cert.pem").toURI();
        lenient().doReturn(privateKey).when(mockSecurityService).getDeviceIdentityPrivateKeyURI();
        lenient().doReturn(certUri).when(mockSecurityService).getDeviceIdentityCertificateURI();
        lenient().doReturn(EncryptionUtils.loadPrivateKeyPair(Paths.get(privateKey)))
                .when(mockSecurityService).getKeyPair(privateKey, certUri);

        // Cloud sync throws on every call
        lenient().doThrow(new SecretManagerException("Network unavailable"))
                .when(secretClient).getSecret(any(GetSecretValueRequest.class));

        kernel = new Kernel();
        kernel.parseArgs("-r", rootDir.toAbsolutePath().toString(), "-i",
                getClass().getResource("config.yaml").toString());

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

        assertTrue(secretManagerRunning.await(10, TimeUnit.SECONDS),
                "Service should reach RUNNING even when cloud sync fails");
    }

    @Test
    void GIVEN_secret_service_WHEN_cloud_sync_slow_THEN_secrets_available_after_sync_completes(
            ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, SecretManagerException.class);
        ignoreExceptionOfType(context, GetSecretException.class);
        URI privateKey = getClass().getResource("privateKey.pem").toURI();
        URI certUri = getClass().getResource("cert.pem").toURI();
        lenient().doReturn(privateKey).when(mockSecurityService).getDeviceIdentityPrivateKeyURI();
        lenient().doReturn(certUri).when(mockSecurityService).getDeviceIdentityCertificateURI();
        lenient().doReturn(EncryptionUtils.loadPrivateKeyPair(Paths.get(privateKey)))
                .when(mockSecurityService).getKeyPair(privateKey, certUri);

        String arn = "arn:aws:secretsmanager:us-east-1:999936977227:secret:Secret1-74lYJh";
        CountDownLatch syncAttempted = new CountDownLatch(1);

        // Cloud sync fails initially (simulating slow/unavailable network)
        lenient().doAnswer(invocation -> {
            syncAttempted.countDown();
            throw new SecretManagerException("Network unavailable");
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

        // Service is running but secrets haven't synced
        assertTrue(secretManagerRunning.await(10, TimeUnit.SECONDS));
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
    void GIVEN_secret_service_WHEN_restarted_without_reinstall_THEN_loads_from_disk_cache() throws Exception {
        startKernelWithConfig("config.yaml", State.RUNNING);

        // Verify secret is available after initial startup
        GreengrassCoreIPCClientV2 clientV2 = IPCTestUtils.connectV2Client(kernel, "ComponentRequestingSecrets");
        software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest req =
                new software.amazon.awssdk.aws.greengrass.model.GetSecretValueRequest();
        req.setSecretId("Secret1");
        req.setVersionStage(CURRENT_LABEL);
        GetSecretValueResponse response = clientV2.getSecretValue(req);
        assertEquals("secretValue", response.getSecretValue().getSecretString());

        // Make cloud unavailable so secrets can only come from disk
        lenient().doThrow(new SecretManagerException("Network unavailable"))
                .when(secretClient).getSecret(any(GetSecretValueRequest.class));

        // Restart the service (not reinstall). startup() no longer reloads the cache; secrets
        // remain served from the persisted in-memory cache, with a lazy reload from the local
        // store as the fallback if the entry is missing.
        SecretManagerService service = kernel.getContext().get(SecretManagerService.class);
        CountDownLatch secretManagerRunning = new CountDownLatch(1);
        kernel.getContext().addGlobalStateChangeListener((GreengrassService svc, State was, State newState) -> {
            if (svc.getName().equals(SecretManagerService.SECRET_MANAGER_SERVICE_NAME)
                    && newState.equals(State.RUNNING)) {
                secretManagerRunning.countDown();
            }
        });
        service.requestRestart();
        assertTrue(secretManagerRunning.await(10, TimeUnit.SECONDS));

        // Secret should still be available after a restart while the cloud is unavailable
        GetSecretValueResponse responseAfterRestart = clientV2.getSecretValue(req);
        assertEquals("secretValue", responseAfterRestart.getSecretValue().getSecretString());
    }

    @Test
    void GIVEN_secret_service_WHEN_reinstalled_THEN_syncs_from_cloud_and_skips_disk_reload() throws Exception {
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
                        .name("Secret1").arn(arn).secretString("updatedAfterReinstall").versionId("newVersionId")
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

        // Now restart the service. startup() does not reload the cache, so the fresh in-memory
        // value synced above is preserved and served after the restart.
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
        assertEquals("updatedAfterReinstall", responseAfterRestart.getSecretValue().getSecretString());
        assertEquals("newVersionId", responseAfterRestart.getVersionId());
    }
}
