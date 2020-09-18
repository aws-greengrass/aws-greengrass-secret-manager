/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.crypto;

import com.amazonaws.encryptionsdk.jce.JceMasterKey;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.UUID;

public class RSAMasterKey implements MasterKey {
    // Metadata used by JCEMasterKey, so that another instance of JCEMasterKey cannot be used
    // to encrypt/decrypt payload even if it uses the same key.
    private static final String KEY_PROVIDER = "gg:secrets";
    private static final String WRAPPING_ALGO = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private JceMasterKey masterKey;

    private RSAMasterKey(final PublicKey publicKey,
                         final PrivateKey privateKey) {
        String keyId = UUID.randomUUID().toString();
        this.masterKey = JceMasterKey.getInstance(publicKey, privateKey, KEY_PROVIDER, keyId, WRAPPING_ALGO);
    }

    public static MasterKey createInstance(final PublicKey publicKey,
                                           final PrivateKey privateKey) {
        return new RSAMasterKey(publicKey, privateKey);
    }

    @Override
    public JceMasterKey getMasterKey() {
        return masterKey;
    }
}
