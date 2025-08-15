package com.jithinnambiar.securitystarter.cache;

import com.jithinnambiar.security.jwt.InMemoryJwkCache;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryJwkCacheTest {
    private RSAKey newRsa(String kid) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();
        return new RSAKey.Builder((java.security.interfaces.RSAPublicKey) kp.getPublic()).privateKey(kp.getPrivate()).keyID(kid).build();
    }

    @Test
    void putGetEvictAndStats() throws Exception {
        InMemoryJwkCache cache = new InMemoryJwkCache(60);
        String uri = "https://jwks";
        assertNull(cache.get(uri));
        RSAKey k1 = newRsa("k1");
        cache.put(uri, new JWKSet(k1));
        assertNotNull(cache.get(uri));
        var statsAfterHit = cache.stats();
        assertTrue(statsAfterHit.hits() >= 1);
        cache.evict(uri);
        assertNull(cache.get(uri));
        var statsAfterEvictMiss = cache.stats();
        assertTrue(statsAfterEvictMiss.misses() >= 1);
    }

    @Test
    void expiry() throws Exception {
        InMemoryJwkCache cache = new InMemoryJwkCache(1); // 1 second TTL
        String uri = "https://jwks-exp";
        cache.put(uri, new JWKSet(newRsa("k2")));
        assertNotNull(cache.get(uri));
        Thread.sleep(1100);
        assertNull(cache.get(uri)); // expired
    }
}

