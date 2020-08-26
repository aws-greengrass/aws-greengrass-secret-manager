package com.aws.iot.greengrass.secretmanager;

import com.aws.iot.greengrass.secretmanager.exception.SecretManagerException;

public interface SecretDao<V> {
    V getAll() throws SecretManagerException;

    void saveAll(V list) throws SecretManagerException;
}
