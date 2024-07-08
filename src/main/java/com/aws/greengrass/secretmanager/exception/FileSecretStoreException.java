package com.aws.greengrass.secretmanager.exception;

public class FileSecretStoreException extends SecretManagerException {
    public FileSecretStoreException(String err, Exception e) {
        super(err, e);
    }
}
