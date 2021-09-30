/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.crypto;

import com.aws.greengrass.dependency.State;
import com.aws.greengrass.deployment.DeviceConfiguration;
import com.aws.greengrass.lifecyclemanager.Kernel;
import com.aws.greengrass.secretmanager.exception.SecretCryptoException;
import com.aws.greengrass.security.SecurityService;
import com.aws.greengrass.security.provider.pkcs11.PKCS11CryptoKeyService;
import com.aws.greengrass.security.provider.pkcs11.softhsm.HSMToken;
import com.aws.greengrass.security.provider.pkcs11.softhsm.SoftHSM;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import com.aws.greengrass.util.EncryptionUtils;
import com.aws.greengrass.util.EncryptionUtilsTest;
import com.aws.greengrass.util.Pair;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static com.aws.greengrass.componentmanager.KernelConfigResolver.CONFIGURATION_CONFIG_KEY;
import static com.aws.greengrass.lifecyclemanager.GreengrassService.SERVICES_NAMESPACE_TOPIC;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith({MockitoExtension.class, GGExtension.class})
public class CrypterTest {
    private static final String DUMMY_STRING = "Hello World !!. This is supposed to be a secret";
    private static final String CONTEXT_STRING = "arn:aws:blah:blah";
    private static final int THIRTY_TWO_KB = 32768;
    private KeyChain keyChain;
    private MasterKey masterKey;
    private KeyPair kp;

    private static final URI PRIVATE_KEY_URI = URI.create("pkcs11:object=iotkey;type=private");
    private static final URI CERTIFICATE_URI = URI.create("pkcs11:object=iotkey;type=cert");

    private static SoftHSM hsm;
    private static HSMToken token;
    private static Kernel kernel;
    @TempDir
    static Path resourcePath;

    static void setupPKCS11() throws Exception {
        kernel = new Kernel();
        hsm = new SoftHSM();
        token = hsm.initToken(
                HSMToken.builder().name("softhsm-pkcs11").label("greengrass1").slotId(0).userPin("7526").build());
        Pair<Path, KeyPair> cert =
                EncryptionUtilsTest.generateCertificateFile(2048, true, resourcePath.resolve("certificate.pem"), false);
        List<X509Certificate> certificateChain = EncryptionUtils.loadX509Certificates(cert.getLeft());
        hsm.importPrivateKey(cert.getRight().getPrivate(), certificateChain.toArray(new Certificate[0]), "iotkey", token);

        startService();
    }

    @AfterAll
    static void afterAll() throws Exception {
        if (kernel != null) {
            kernel.shutdown();
            hsm.cleanUpTokens();
            try {
                PKCS11 pkcs11 = PKCS11.getInstance(hsm.getSharedLibraryPath().toString(), null, null, true);
                pkcs11.C_Finalize(PKCS11Constants.NULL_PTR);
            } catch (PKCS11Exception | IOException e) {
                //ignore
            }
        }
    }

    private static void startService() throws Exception {
        CountDownLatch serviceRunning = new CountDownLatch(1);
        kernel.parseArgs();
        kernel.getConfig()
                .lookup(SERVICES_NAMESPACE_TOPIC, PKCS11CryptoKeyService.PKCS11_SERVICE_NAME, CONFIGURATION_CONFIG_KEY,
                        PKCS11CryptoKeyService.NAME_TOPIC).withValue(token.getName());
        kernel.getConfig()
                .lookup(SERVICES_NAMESPACE_TOPIC, PKCS11CryptoKeyService.PKCS11_SERVICE_NAME, CONFIGURATION_CONFIG_KEY,
                        PKCS11CryptoKeyService.LIBRARY_TOPIC).withValue(hsm.getSharedLibraryPath().toString());
        kernel.getConfig()
                .lookup(SERVICES_NAMESPACE_TOPIC, PKCS11CryptoKeyService.PKCS11_SERVICE_NAME, CONFIGURATION_CONFIG_KEY,
                        PKCS11CryptoKeyService.USER_PIN_TOPIC).withValue(token.getUserPin());
        int slotId = token.getSlotId();
        kernel.getConfig()
                .lookup(SERVICES_NAMESPACE_TOPIC, PKCS11CryptoKeyService.PKCS11_SERVICE_NAME, CONFIGURATION_CONFIG_KEY,
                        PKCS11CryptoKeyService.SLOT_ID_TOPIC).withValue(slotId);
        kernel.getContext().get(DeviceConfiguration.class).getPrivateKeyFilePath()
                .withValue(PRIVATE_KEY_URI.toString());
        kernel.getContext().get(DeviceConfiguration.class).getCertificateFilePath()
                .withValue(CERTIFICATE_URI.toString());
        kernel.getContext().addGlobalStateChangeListener((service, was, newState) -> {
            if (PKCS11CryptoKeyService.PKCS11_SERVICE_NAME.equals(service.getName()) && service.getState()
                    .equals(State.RUNNING)) {
                serviceRunning.countDown();
            }
        });
        kernel.launch();
        assertTrue(serviceRunning.await(10, TimeUnit.SECONDS));
    }

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

    @DisabledOnOs(OS.WINDOWS)
    @Test
    void GIVEN_pkcs11_secret_key_WHEN_crypter_encrypts_THEN_decrypt_works() throws Exception {
        setupPKCS11();
        SecurityService security = kernel.getContext().get(SecurityService.class);
        KeyPair pkcs11Kp = security.getKeyPair(security.getDeviceIdentityPrivateKeyURI(),
                security.getDeviceIdentityCertificateURI());
        MasterKey pkcs11MasterKey = RSAMasterKey.createInstance(pkcs11Kp.getPublic(), pkcs11Kp.getPrivate());
        KeyChain pkcs11KeyChain = new KeyChain();
        pkcs11KeyChain.addMasterKey(pkcs11MasterKey);

        byte[] plainText = DUMMY_STRING.getBytes(StandardCharsets.UTF_8);
        Crypter crypter = new Crypter(pkcs11KeyChain);
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
