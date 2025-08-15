package com.jithinnambiar.security.jwt;

import com.nimbusds.jose.jwk.JWKSet;

/** Simple abstraction for JWK cache implementations. */
public interface JwkCache {
    JWKSet get(String jwksUri);
    void put(String jwksUri, JWKSet jwkSet);
    void evict(String jwksUri);
    default CacheStats stats() { return CacheStats.EMPTY; }
    record CacheStats(long hits,long misses){ static final CacheStats EMPTY=new CacheStats(0,0);} }
