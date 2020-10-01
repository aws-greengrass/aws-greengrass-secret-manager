/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.crypto;

import com.aws.greengrass.secretmanager.exception.SecretCryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Class that helps reading from keys/certs from files.
 */
public class PemFile {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String RSA_ALGO = "RSA";
    private static final String JCE_PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

    private PemFile() {

    }

    private static PemObject readPem(String filePath) throws SecretCryptoException {
        try (FileInputStream fileInputStream = new FileInputStream(filePath);
             InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream, StandardCharsets.UTF_8);
             PEMParser pemParser = new PEMParser(inputStreamReader)) {
            PemObject pemReaderObject = pemParser.readPemObject();
            if (pemReaderObject == null) {
                throw new SecretCryptoException("Error while reading " + filePath + ". It is not a valid PEM file");
            }
            return pemReaderObject;
        } catch (IOException e) {
            throw new SecretCryptoException(e);
        }
    }

    /**
     * Read RSA private key from a given file containing key in PKCS8 format.
     * @param filePath file containing RSA private key
     * @return corresponding java @{PrivateKey}
     * @throws SecretCryptoException when there is error generating the key from file
     */
    public static PrivateKey generatePrivateKey(String filePath) throws SecretCryptoException {
        PemObject pemObject = readPem(filePath);
        try {
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGO, JCE_PROVIDER);
            return keyFactory.generatePrivate(privKeySpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            throw new SecretCryptoException("Unable to read private key", e);
        }
    }

    /**
     * Read DER encoded X.509 certificate from a file and generate corresponding public key.
     * @param path path to the file containing certificate
     * @return corresponding java @{PublickKey}
     * @throws SecretCryptoException when there is error generating the key from file
     */
    public static PublicKey generatePublicKeyFromCert(String path) throws SecretCryptoException {
        try (FileInputStream fileInputStream = new FileInputStream(path)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", JCE_PROVIDER);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(fileInputStream);
            PublicKey publicKey = cert.getPublicKey();
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGO, JCE_PROVIDER);
            return keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (Exception e) {
            throw new SecretCryptoException(e);
        }
    }
}

