/*
 * Copyright Amazon.com Inc. or its affiliates.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager;

import com.aws.greengrass.ipc.Startable;
import generated.software.amazon.awssdk.iot.greengrass.GreengrassCoreIPCService;

import javax.inject.Inject;

public class SecretManagerIPCService implements Startable {
    @Inject
    SecretManagerIPCAgent secretManagerIPCAgent;

    @Inject
    private GreengrassCoreIPCService greengrassCoreIPCService;

    @Override
    public void startup() {
        greengrassCoreIPCService.setGetSecretValueHandler(
                (context) -> secretManagerIPCAgent.getSecretValueOperationHandler(context));
    }
}
