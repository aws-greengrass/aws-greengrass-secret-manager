/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager;

import com.aws.greengrass.secretmanager.exception.SecretManagerException;

public interface SecretDao<V> {
    V getAll() throws SecretManagerException;

    void saveAll(V list) throws SecretManagerException;
}
