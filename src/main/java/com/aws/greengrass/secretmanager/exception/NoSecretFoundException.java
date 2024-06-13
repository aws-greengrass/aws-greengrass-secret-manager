/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.exception;

public class NoSecretFoundException extends SecretManagerException {
    public NoSecretFoundException(String err) {
        super(err);
    }
}
