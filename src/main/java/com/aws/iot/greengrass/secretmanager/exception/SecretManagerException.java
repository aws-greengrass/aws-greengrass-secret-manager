package com.aws.iot.greengrass.secretmanager.exception;

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
