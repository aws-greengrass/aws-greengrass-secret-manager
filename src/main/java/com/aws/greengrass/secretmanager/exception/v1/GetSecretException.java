package com.aws.greengrass.secretmanager.exception.v1;

import lombok.Getter;

public class GetSecretException extends Exception {
    @Getter
    private final int status;

    public GetSecretException(int status, String err) {
        super(err);
        this.status = status;
    }

    public GetSecretException(int status, Exception err) {
        super(err);
        this.status = status;
    }

    public GetSecretException(int status, String err, Exception e) {
        super(err, e);
        this.status = status;
    }
}
