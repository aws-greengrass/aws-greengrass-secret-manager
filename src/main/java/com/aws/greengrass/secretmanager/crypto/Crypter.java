/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.crypto;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.multi.MultipleProviderFactory;
import com.aws.greengrass.secretmanager.exception.SecretCryptoException;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Class which performs encryption/decryption using key chain installed during initialization.
 */
public final class Crypter {
    private static final String CONTEXT_STR = "Context";
    private final KeyChain keyChain;

    /**
     * Constructor.
     * @param keyChain Keychain holding keys for performing decrypt/encrypt operations.
     * @throws SecretCryptoException if key chain is invalid.
     */
    public Crypter(final KeyChain keyChain) throws SecretCryptoException {
        if (keyChain.getMasterKey() == null) {
            throw new SecretCryptoException("Empty Key chain provided");
        }
        this.keyChain = keyChain;
    }

    /**
     * Decrypt a cipher text using installed key chain.
     * @param payload cipher text to be decrypted.
     * @param context additional context to be matched with the context stored with encrypted data.
     * @return decrypted plain text.
     * @throws SecretCryptoException when inputs are invalid, or context mismatches or decryption fails.
     */
    public byte[] decrypt(final byte[] payload, final String context) throws SecretCryptoException {
        try {
            if (context == null || context.isEmpty()) {
                throw new SecretCryptoException("Invalid context provided");
            }
            if (payload.length == 0) {
                throw new SecretCryptoException("Empty input payload provided");
            }
            List<JceMasterKey> keyList = keyChain.getKeyProviders();
            AwsCrypto awsCrypto = new AwsCrypto();
            final MasterKeyProvider<?> provider = MultipleProviderFactory.buildMultiProvider(keyList);
            final CryptoResult<byte[], ?> decryptResult = awsCrypto.decryptData(provider, payload);
            byte[] decryptedPayload = decryptResult.getResult();
            Map<String,String> decryptedPayloadContext = decryptResult.getEncryptionContext();
            if (!context.equals(decryptedPayloadContext.get(CONTEXT_STR))) {
                throw new SecretCryptoException(
                        String.format("Context mismatch, expected %s, but found %s",
                                context,
                                decryptedPayloadContext));
            }
            return decryptedPayload;
        } catch (Exception e) {
            throw new SecretCryptoException(e);
        }
    }

    /**
     * Encrypt a plain text using installed key chain.
     * @param plainText text to be encrypted
     * @param context Additional context stored with encrypted text.
     * @return cipher text with additional context as provided.
     * @throws SecretCryptoException if parameters are invalid or if there is any issue during encryption.
     */
    public byte[] encrypt(final byte[] plainText, final String context) throws SecretCryptoException {
        try {
            if (context == null || context.isEmpty()) {
                throw new SecretCryptoException("Invalid context provided");
            }
            if (plainText.length == 0) {
                throw new SecretCryptoException("Empty input plainText provided");
            }
            // masterKey cannot be null as keychain is add only and empty key chain is not allowed.
            JceMasterKey masterKey = keyChain.getMasterKey();
            final AwsCrypto awsCrypto = new AwsCrypto();
            final Map<String, String> encryptionContext = Collections.singletonMap(CONTEXT_STR, context);
            final CryptoResult<byte[], ?> encryptionResult =
                    awsCrypto.encryptData(masterKey, plainText, encryptionContext);
            return encryptionResult.getResult();
        } catch (Exception e) {
            throw new SecretCryptoException(e);
        }
    }
}
