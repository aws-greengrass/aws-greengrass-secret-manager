package com.aws.iot.greengrass.secretmanager;


import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class MemorySecretDao implements SecretDao<String, GetSecretValueResult> {

    private ConcurrentHashMap<String, GetSecretValueResult> store = new ConcurrentHashMap<>();

    /**
     * Get object for a single key.
     * @param key key for the data object to access
     * @return data object associated with key
     */
    public Optional<GetSecretValueResult> get(String key) {
        if (store.containsKey(key)) {
            return Optional.of(store.get(key));
        }
        return Optional.empty();
    }

    /**
     * get all objects stored in this store.
     * @return list of all objects in store
     */
    public List<GetSecretValueResult> getAll() {
        return store.values().stream().collect(Collectors.toList());
    }

    /**
     * Store a key in the store.
     * @param key key associated with the object to store
     * @param value object to be stored
     */
    public void save(String key, GetSecretValueResult value) {
        store.putIfAbsent(key, value);
    }
}
