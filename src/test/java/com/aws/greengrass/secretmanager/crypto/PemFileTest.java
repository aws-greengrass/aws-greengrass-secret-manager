/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.crypto;

import com.aws.greengrass.testcommons.testutilities.GGExtension;
import com.aws.greengrass.util.EncryptionUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith({MockitoExtension.class, GGExtension.class})
public class PemFileTest {
    private final static String HELLO_WORLD_STR = "HELLO WORLD";

    @Test
    void GIVEN_pem_file_WHEN_pemfile_parsed_THEN_works() throws Exception {
        URL privateKeyUrl = getClass().getResource("privateKey.pem");
        KeyPair kp = EncryptionUtils.loadPrivateKeyPair(Paths.get(privateKeyUrl.toURI()));

        MasterKey masterKey = RSAMasterKey.createInstance(kp.getPublic(), kp.getPrivate());
        KeyChain keyChain = new KeyChain();
        keyChain.addMasterKey(masterKey);

        byte[] plainText = HELLO_WORLD_STR.getBytes(StandardCharsets.UTF_8);
        Crypter crypter = new Crypter(keyChain);
        byte[] cipherText = crypter.encrypt(plainText, "test");
        byte[] result = crypter.decrypt(cipherText, "test");

        assertEquals(HELLO_WORLD_STR, new String(result));
    }
}
