package com.aws.iot.greengrass.secretmanager;

import java.util.List;
import java.util.Optional;

public interface SecretDao<K, V> {
    Optional<V> get(K id);

    List<V> getAll();

    void save(K id, V value);
}
