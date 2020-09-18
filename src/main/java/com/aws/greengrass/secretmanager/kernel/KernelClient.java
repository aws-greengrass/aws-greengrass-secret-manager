/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.kernel;

import com.aws.greengrass.config.Configuration;
import com.aws.greengrass.deployment.DeviceConfiguration;
import com.aws.greengrass.lifecyclemanager.Kernel;
import com.aws.greengrass.util.Coerce;

import javax.inject.Inject;

public class KernelClient {
    private final Kernel kernel;
    private final DeviceConfiguration deviceConfiguration;

    @Inject
    KernelClient(Kernel kernel,
                 DeviceConfiguration deviceConfiguration) {
        this.kernel = kernel;
        this.deviceConfiguration = deviceConfiguration;
    }

    public String getPrivateKeyPath() {
        return Coerce.toString(deviceConfiguration.getPrivateKeyFilePath());
    }

    public String getCertPath() {
        return Coerce.toString(deviceConfiguration.getCertificateFilePath());
    }

    public boolean isAuthorized() {
        // TODO: integrate with authorization service
        return true;
    }

    public Configuration getConfig() {
        return kernel.getConfig();
    }
}
