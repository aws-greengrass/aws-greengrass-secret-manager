package com.aws.iot.greengrass.secretmanager.exception;

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
