package com.aws.iot.greengrass.secretmanager.crypto;

import com.amazonaws.encryptionsdk.jce.JceMasterKey;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.UUID;

public class RSAMasterKey implements MasterKey {

    // TODO: see how this works
    private static final String KEY_PROVIDER = "gg:md5";
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
