/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.kernel;

import com.aws.greengrass.config.Configuration;
import com.aws.greengrass.lifecyclemanager.Kernel;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith({MockitoExtension.class, GGExtension.class})
public class kernelClientTest {

    private static final String mockKeyPath = "/test/keypath";
    private static final String mockCertPath = "/test/certpath";

    @Mock
    Configuration mockConfiguration;

    @Mock
    Kernel mockKernel;

    @Test
    void GIVEN_kernel_client_WHEN_get_context_THEN_works() {
        KernelClient kernelClient = new KernelClient(mockKernel);
        when(mockKernel.getConfig()).thenReturn(mockConfiguration);
        assertEquals(mockConfiguration, kernelClient.getConfig());
    }
}
