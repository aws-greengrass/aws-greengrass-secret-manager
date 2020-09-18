/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.crypto;

import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import lombok.Getter;

import java.util.ArrayList;
import java.util.List;

/**
 * Class to hold keys for crypto, Only allows addition of keys. Keys can be a mix of symmetric/assymetric and KMS
 * keys as supported by aws encryption SDK. For now we only provide RSA assymetric keys.
 */
public class KeyChain {

    @Getter
    private List<JceMasterKey> keyProviders = new ArrayList<>();

    /**
     * Add a master key to this key chain.
     * @param masterKey master key to be added.
     */
    public void addMasterKey(final MasterKey masterKey) {
        keyProviders.add(masterKey.getMasterKey());
    }

    /**
     * Return the first master key in chain. This is useful for aws encryption SDK as it can be
     * encrypted using any key from the chain, as decrypt requires the whole key chain and would
     * decrypt as long as any key is able to decrypt the payload.
     * @return First master key in the chain.
     */
    public JceMasterKey getMasterKey() {
        if (keyProviders.isEmpty()) {
            return null;
        }
        return keyProviders.get(0);
    }
}
