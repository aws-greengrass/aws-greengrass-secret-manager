/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.kernel;

import com.aws.greengrass.config.Configuration;
import com.aws.greengrass.lifecyclemanager.Kernel;

import javax.inject.Inject;

public class KernelClient {
    private final Kernel kernel;

    @Inject
    KernelClient(Kernel kernel) {
        this.kernel = kernel;
    }

    public Configuration getConfig() {
        return kernel.getConfig();
    }
}
