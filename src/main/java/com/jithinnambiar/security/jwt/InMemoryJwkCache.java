package com.jithinnambiar.security.jwt;


import com.nimbusds.jose.jwk.JWKSet;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryJwkCache implements JwkCache {

    private static class Entry {
        final JWKSet jwkSet;
        final Instant expiresAt;
        Entry(JWKSet set, Instant expiresAt) {
            this.jwkSet = set;
            this.expiresAt = expiresAt;
        }
    }

    private final Map<String, Entry> delegate = new ConcurrentHashMap<>();
    private final long ttlSeconds;
    private volatile long hits;
    private volatile long misses;

    public InMemoryJwkCache(long ttlSeconds) {
        this.ttlSeconds = ttlSeconds;
    }

    @Override
    public JWKSet get(String jwksUri) {
        var entry = delegate.get(jwksUri);
        if (entry == null) {
            misses++;
            return null;
        }
        if (Instant.now().isAfter(entry.expiresAt)) {
            delegate.remove(jwksUri);
            misses++;
            return null;
        }
        hits++;
        return entry.jwkSet;
    }

    @Override
    public void put(String jwksUri, JWKSet jwkSet) {
        delegate.put(jwksUri, new Entry(jwkSet, Instant.now().plusSeconds(ttlSeconds)));
    }

    @Override
    public void evict(String jwksUri) {
        delegate.remove(jwksUri);
    }

    @Override
    public CacheStats stats() {
        return new CacheStats(hits, misses);
    }
}