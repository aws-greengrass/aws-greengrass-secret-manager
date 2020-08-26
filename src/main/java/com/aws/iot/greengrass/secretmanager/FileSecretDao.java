package com.aws.iot.greengrass.secretmanager;

import com.aws.iot.greengrass.secretmanager.exception.SecretManagerException;
import com.aws.iot.greengrass.secretmanager.kernel.KernelClient;
import com.aws.iot.greengrass.secretmanager.model.SecretDocument;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import javax.inject.Inject;

/**
 * File based DAO for secrets. This class persists {@link SecretDocument} to a pre defined
 * directory. Both getAll and saveAll are protected by {@link synchronized}, which guarantees
 * only a single thread can either read or write the store at any point of time. The class
 * is also immutable with all fields being final.
 */
public class FileSecretDao implements SecretDao<SecretDocument> {
    private static final ObjectMapper JSON_OBJECT_MAPPER =
            new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
                    .registerModule(new JavaTimeModule());
    public static final String SECRET_FILE = "secrets.json";
    public static final String SECRETS_DIR = "secrets";
    private final Path filePath;

    /**
     * Constructor.
     * @param kernelClient kernel client for accessing kernel root dir
     * @throws SecretManagerException if root dir does not exist
     */
    @Inject
    public FileSecretDao(KernelClient kernelClient) throws SecretManagerException {
        Path rootDir = kernelClient.getRoot();
        Path secretsDir = setUpDir(rootDir);
        filePath = secretsDir.resolve(SECRET_FILE);
    }

    private Path setUpDir(Path rootDir) throws SecretManagerException {
        // TODO: Setup permissions for local db
        Path secretDirectory = rootDir.resolve(SECRETS_DIR);
        if (!Files.exists(secretDirectory) || !Files.isDirectory(secretDirectory)) {
            try {
                Files.createDirectories(secretDirectory);
            } catch (IOException e) {
                throw new SecretManagerException("Failed to create secret dir");
            }
        }
        return secretDirectory;
    }

    /**
     * Retrieve secret document from underlying file store.
     * @return {@link SecretDocument} containing all persisted secrets
     * @throws SecretManagerException when there is any issue reading the store.
     */
    public synchronized SecretDocument getAll() throws SecretManagerException {
        Objects.requireNonNull(filePath);
        try (InputStream input = Files.newInputStream(filePath)) {
            return JSON_OBJECT_MAPPER.readValue(input, new TypeReference<SecretDocument>(){});
        } catch (IOException e) {
            throw new SecretManagerException(e);
        }
    }

    /**
     * Save a secret document to underlying file store.
     * @param doc {@link SecretDocument} containing list of secrets to persist
     * @throws SecretManagerException when there is a problem writing to underlying store
     */
    public synchronized void saveAll(SecretDocument doc) throws SecretManagerException {
        try {
            Objects.requireNonNull(filePath);
            Files.deleteIfExists(filePath);
            Files.createFile(filePath);
            OutputStream out = Files.newOutputStream(filePath);
            JSON_OBJECT_MAPPER.writeValue(out, doc);
        } catch (IOException e) {
            throw new SecretManagerException(e);
        }
    }
}

