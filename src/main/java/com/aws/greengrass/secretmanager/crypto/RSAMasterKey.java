/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.crypto;

import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.aws.greengrass.secretmanager.exception.SecretCryptoException;
import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSAMasterKey implements MasterKey {
    // Metadata used by JCEMasterKey, so that another instance of JCEMasterKey cannot be used
    // to encrypt/decrypt payload even if it uses the same key.
    private static final String KEY_PROVIDER = "gg:secrets";
    private static final String WRAPPING_ALGO = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private JceMasterKey masterKey;

    private RSAMasterKey(final PublicKey publicKey,
                         final PrivateKey privateKey) throws SecretCryptoException {
        String keyId = publicKeySHA(publicKey);
        this.masterKey = JceMasterKey.getInstance(publicKey, privateKey, KEY_PROVIDER, keyId, WRAPPING_ALGO);
    }

    public static MasterKey createInstance(final PublicKey publicKey,
                                           final PrivateKey privateKey) throws SecretCryptoException {
        return new RSAMasterKey(publicKey, privateKey);
    }

    private String publicKeySHA(final PublicKey key) throws SecretCryptoException {
        try {
            byte[] sha1 = MessageDigest.getInstance("SHA-1").digest(key.getEncoded());
            return new String(Hex.encode(sha1));
        } catch (NoSuchAlgorithmException e) {
            throw new SecretCryptoException("Unable to get SHA-1 provider", e);
        }
    }

    @Override
    public JceMasterKey getMasterKey() {
        return masterKey;
    }
}
