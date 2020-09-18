/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.exception;

public class SecretCryptoException extends Exception {
    public SecretCryptoException(String err) {
        super(err);
    }

    public SecretCryptoException(Exception err) {
        super(err);
    }

    public SecretCryptoException(String err, Exception e) {
        super(err, e);
    }
}
