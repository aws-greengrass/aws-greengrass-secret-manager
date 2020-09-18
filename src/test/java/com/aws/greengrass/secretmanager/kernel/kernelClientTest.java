/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.kernel;

import com.aws.greengrass.config.Configuration;
import com.aws.greengrass.config.Topic;
import com.aws.greengrass.deployment.DeviceConfiguration;
import com.aws.greengrass.lifecyclemanager.Kernel;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith({MockitoExtension.class, GGExtension.class})
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
