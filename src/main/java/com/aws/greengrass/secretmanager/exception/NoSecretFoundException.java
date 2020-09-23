/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.exception;

public class NoSecretFoundException extends SecretManagerException {
    public NoSecretFoundException(String err) {
        super(err);
    }

    public NoSecretFoundException(Exception err) {
        super(err);
    }

    public NoSecretFoundException(String err, Exception e) {
        super(err, e);
    }
}
