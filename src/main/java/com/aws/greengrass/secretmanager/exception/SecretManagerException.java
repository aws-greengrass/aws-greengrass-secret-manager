/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.exception;

public class SecretManagerException extends Exception {
    public SecretManagerException(String err) {
        super(err);
    }

    public SecretManagerException(Exception err) {
        super(err);
    }

    public SecretManagerException(String err, Exception e) {
        super(err, e);
    }
}
