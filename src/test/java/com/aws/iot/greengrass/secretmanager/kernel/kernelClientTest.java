package com.aws.iot.greengrass.secretmanager.kernel;

import com.aws.iot.evergreen.config.Configuration;
import com.aws.iot.evergreen.config.Topic;
import com.aws.iot.evergreen.deployment.DeviceConfiguration;
import com.aws.iot.evergreen.kernel.Kernel;
import com.aws.iot.evergreen.testcommons.testutilities.EGExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith({MockitoExtension.class, EGExtension.class})
public class kernelClientTest {

    private static final String mockKeyPath = "/test/keypath";
    private static final String mockCertPath = "/test/certpath";

    @Mock
    Configuration mockConfiguration;

    @Mock
    Kernel mockKernel;

    @Mock
    DeviceConfiguration mockDeviceConfiguration;

    @Test
    void GIVEN_kernel_client_WHEN_get_config_THEN_works() {
        KernelClient kernelClient = new KernelClient(mockKernel, mockDeviceConfiguration);
        Topic privKeyTopicMock = mock(Topic.class);
        Topic pubKeyTopicMock = mock(Topic.class);

        when(privKeyTopicMock.getOnce()).thenReturn(mockKeyPath);
        when(pubKeyTopicMock.getOnce()).thenReturn(mockCertPath);

        when(mockDeviceConfiguration.getPrivateKeyFilePath()).thenReturn(privKeyTopicMock);
        when(mockDeviceConfiguration.getCertificateFilePath()).thenReturn(pubKeyTopicMock);

        assertEquals(mockKeyPath, kernelClient.getPrivateKeyPath());
        assertEquals(mockCertPath, kernelClient.getCertPath());
    }

    @Test
    void GIVEN_kernel_client_WHEN_get_contextt_THEN_works() {
        KernelClient kernelClient = new KernelClient(mockKernel, mockDeviceConfiguration);
        when(mockKernel.getConfig()).thenReturn(mockConfiguration);
        assertEquals(mockConfiguration, kernelClient.getConfig());
    }
}
