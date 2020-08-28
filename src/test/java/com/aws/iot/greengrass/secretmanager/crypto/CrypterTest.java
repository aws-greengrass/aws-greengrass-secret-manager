package com.aws.iot.greengrass.secretmanager.crypto;

import com.aws.iot.evergreen.testcommons.testutilities.EGExtension;
import com.aws.iot.greengrass.secretmanager.exception.SecretCryptoException;
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

@ExtendWith({MockitoExtension.class, EGExtension.class})
public class CrypterTest {
    private static final String DUMMY_STRING = "Hello World !!. This is supposed to be a secret";
    private static final String CONTEXT_STRING = "arn:aws:blah:blah";
    private static final int THIRTY_TWO_KB = 32768;
    private KeyChain keyChain;
    private MasterKey masterKey;

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
        KeyPair kp = getDummyKey();
        masterKey = RSAMasterKey.createInstance(kp.getPublic(), kp.getPrivate());
        keyChain = new KeyChain();
        keyChain.addMasterKey(masterKey);
    }

    @Test
    void GIVEN_secret_key_WHEN_crypter_encrypts_THEN_decrypt_works() throws SecretCryptoException {
        byte[] plainText = DUMMY_STRING.getBytes(StandardCharsets.UTF_8);
        Crypter crypter = new Crypter(keyChain);
        byte[] cipherText = crypter.encrypt(plainText, CONTEXT_STRING);

        byte[] result = crypter.decrypt(cipherText, CONTEXT_STRING);
        assertEquals(DUMMY_STRING, new String(result, StandardCharsets.UTF_8));

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
