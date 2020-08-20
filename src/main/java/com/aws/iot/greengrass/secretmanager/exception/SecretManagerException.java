package com.aws.iot.greengrass.secretmanager.exception;

public class SecretManagerException extends Exception {
    public SecretManagerException(String err) {
        super(err);
    }
}
