/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager;

import com.aws.greengrass.testcommons.testutilities.ExceptionLogProtector;
import org.junit.jupiter.api.extension.ExtensionContext;

public class TestUtil {
    public static void ignoreErrors(ExtensionContext context) {
        ExceptionLogProtector.ignoreExceptionWithMessage(context, "PKCS11 missing required configuration value for library");
    }
}
