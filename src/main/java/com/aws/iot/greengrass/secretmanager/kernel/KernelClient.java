package com.aws.iot.greengrass.secretmanager.kernel;

import com.aws.iot.evergreen.config.Configuration;
import com.aws.iot.evergreen.dependency.Context;
import com.aws.iot.evergreen.deployment.DeviceConfiguration;
import com.aws.iot.evergreen.kernel.Kernel;
import com.aws.iot.evergreen.util.Coerce;

import java.nio.file.Path;
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
