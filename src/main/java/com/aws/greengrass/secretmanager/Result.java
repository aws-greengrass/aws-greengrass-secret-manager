/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager;

public class Result<T> {
    private boolean set;
    private T value;

    public Result() {
    }

    public Result(T t) {
        this.value = t;
        this.set = true;
    }

    /**
     * Set the value.
     *
     * @param t new value
     * @return this
     */
    public synchronized Result<T> set(T t) {
        this.value = t;
        this.set = true;
        this.notifyAll();
        return this;
    }

    public boolean isSet() {
        return set;
    }

    public T getValue() {
        return value;
    }
}
