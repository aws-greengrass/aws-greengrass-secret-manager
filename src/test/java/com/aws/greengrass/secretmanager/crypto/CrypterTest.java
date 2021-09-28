/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.crypto;

import com.aws.greengrass.secretmanager.exception.SecretCryptoException;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith({MockitoExtension.class, GGExtension.class})
public class CrypterTest {
    private static final String DUMMY_STRING = "Hello World !!. This is supposed to be a secret";
    private static final String CONTEXT_STRING = "arn:aws:blah:blah";
    private static final int THIRTY_TWO_KB = 32768;
    private KeyChain keyChain;
    private MasterKey masterKey;
    private KeyPair kp;

    private KeyPair getDummyKey() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private String getRandomString(int size) {
        byte[] array = new byte[size];
        new Random().nextBytes(array);
        return new String(array, StandardCharsets.UTF_8);
    }

    @BeforeEach
    void createKeyChain() throws SecretCryptoException, NoSuchAlgorithmException {
        kp = getDummyKey();
        masterKey = RSAMasterKey.createInstance(kp.getPublic(), kp.getPrivate());
        keyChain = new KeyChain();
        keyChain.addMasterKey(masterKey);
    }

    @Test
    void GIVEN_secret_key_WHEN_crypter_encrypts_THEN_decrypt_works()
            throws SecretCryptoException {
        byte[] plainText = DUMMY_STRING.getBytes(StandardCharsets.UTF_8);
        Crypter crypter = new Crypter(keyChain);
        byte[] cipherText = crypter.encrypt(plainText, CONTEXT_STRING);
        byte[] result = crypter.decrypt(cipherText, CONTEXT_STRING);
        assertEquals(DUMMY_STRING, new String(result, StandardCharsets.UTF_8));

        // Try creating a new Crypter instance for same key pair, it should be able to decrypt as well
        MasterKey anotherMasterKey = RSAMasterKey.createInstance(kp.getPublic(), kp.getPrivate());
        KeyChain anotherKeyChain = new KeyChain();
        anotherKeyChain.addMasterKey(anotherMasterKey);
        Crypter anotherCrypter = new Crypter(anotherKeyChain);
        byte[] anotherResult = anotherCrypter.decrypt(cipherText, CONTEXT_STRING);
        assertEquals(DUMMY_STRING, new String(anotherResult, StandardCharsets.UTF_8));

        // Try a large string now
        String largeString = getRandomString(THIRTY_TWO_KB);
        plainText = largeString.getBytes(StandardCharsets.UTF_8);
        cipherText = crypter.encrypt(plainText, CONTEXT_STRING);
        result = crypter.decrypt(cipherText, CONTEXT_STRING);
        assertEquals(largeString, new String(result, StandardCharsets.UTF_8));
    }

    @Test
    void GIVEN_crypter_WHEN_provided_wrong_context_THEN_fails() throws SecretCryptoException {
        byte[] plainText = DUMMY_STRING.getBytes(StandardCharsets.UTF_8);
        Crypter crypter = new Crypter(keyChain);

        byte[] cipherText = crypter.encrypt(plainText, CONTEXT_STRING);

        // Try decrypting with a different context
        assertThrows(SecretCryptoException.class, () -> crypter.decrypt(cipherText, "Invalid Context"));
        assertThrows(SecretCryptoException.class, () -> crypter.decrypt(cipherText, null));
        assertThrows(SecretCryptoException.class, () -> crypter.decrypt(cipherText, ""));
    }

    @Test
    void GIVEN_crypter_WHEN_provided_invalid_input_THEN_fails() throws SecretCryptoException {
        Crypter crypter = new Crypter(keyChain);
        assertThrows(SecretCryptoException.class, () -> crypter.encrypt("".getBytes(StandardCharsets.UTF_8), CONTEXT_STRING));
        assertThrows(SecretCryptoException.class, () -> crypter.encrypt(new byte[]{}, CONTEXT_STRING));

        assertThrows(SecretCryptoException.class, () -> crypter.decrypt("".getBytes(StandardCharsets.UTF_8), CONTEXT_STRING));
        assertThrows(SecretCryptoException.class, () -> crypter.decrypt(new byte[]{}, CONTEXT_STRING));
    }
}
