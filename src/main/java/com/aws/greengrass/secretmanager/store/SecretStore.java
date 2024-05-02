/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.store;

import com.aws.greengrass.secretmanager.exception.SecretManagerException;
import com.fasterxml.jackson.core.JsonProcessingException;

public interface SecretStore<V, T> {
    V getAll() throws SecretManagerException;

    void saveAll(V list) throws SecretManagerException;

    T get(String secretArn, String label) throws SecretManagerException;

    void save(T encryptedResult) throws SecretManagerException, JsonProcessingException;
}
