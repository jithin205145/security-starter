package com.jithinnambiar.securitystarter.jwt;

import com.jithinnambiar.security.SecurityProperties;
import com.jithinnambiar.security.jwt.JwkCache;
import com.jithinnambiar.security.jwt.JwtTokenValidator;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenValidatorTest {
    private SecurityProperties props;
    private RSAKey rsaKey;
    private String issuer;
    private String audience;
    private String jwksUri;
    private JwkCache cache;

    @BeforeEach
    void setUp() throws Exception {
        issuer = "https://issuer.example";
        audience = "api";
        jwksUri = "https://issuer.example/jwks";
        rsaKey = com.jithinnambiar.securitystarter.util.JwtTestUtil.generateRsaJwk("kid1");
        props = new SecurityProperties();
        SecurityProperties.IssuerProperties ip = new SecurityProperties.IssuerProperties();
        ip.setIssuerUri(issuer);
        ip.setJwksUri(jwksUri);
        ip.setAudience(audience);
        ip.setProvider(SecurityProperties.ProviderType.GENERIC);
        props.getIssuers().add(ip);
        cache = new JwkCache() {
            private JWKSet set = new JWKSet(rsaKey.toPublicJWK());
            @Override public JWKSet get(String uri) { return uri.equals(jwksUri) ? set : null; }
            @Override public void put(String uri, JWKSet jwkSet) { this.set = jwkSet; }
            @Override public void evict(String uri) { this.set = null; }
        };
    }

    private String buildToken(Instant exp, RSAKey key, String kidOverride) throws Exception {
        var claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .subject("subj")
                .expirationTime(Date.from(exp))
                .issueTime(new Date())
                .jwtID(UUID.randomUUID().toString())
                .build();
        var header = new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
                .keyID(kidOverride)
                .build();
        var jwt = new SignedJWT(header, claims);
        jwt.sign(new com.nimbusds.jose.crypto.RSASSASigner(key));
        return jwt.serialize();
    }

    @Test
    void validToken() throws Exception {
        JwtTokenValidator validator = new JwtTokenValidator(props, cache);
        String token = buildToken(Instant.now().plusSeconds(300), rsaKey, rsaKey.getKeyID());
        var result = validator.validate(token);
        assertTrue(result.isValid());
        assertNotNull(result.getIssuer());
    }

    @Test
    void expiredToken() throws Exception {
        JwtTokenValidator validator = new JwtTokenValidator(props, cache);
        // Expire far enough in past to exceed default 60s skew
        String token = buildToken(Instant.now().minusSeconds(180), rsaKey, rsaKey.getKeyID());
        var result = validator.validate(token);
        assertFalse(result.isValid());
        assertEquals("Token expired or not yet valid", result.getError());
    }

    @Test
    void audienceMismatch() throws Exception {
        // change expected audience so token audience mismatches
        props.getIssuers().get(0).setAudience("different");
        JwtTokenValidator validator = new JwtTokenValidator(props, cache);
        String token = buildToken(Instant.now().plusSeconds(60), rsaKey, rsaKey.getKeyID());
        var result = validator.validate(token);
        assertFalse(result.isValid());
        assertEquals("Audience mismatch", result.getError());
    }

    @Test
    void unknownIssuer() throws Exception {
        props.getIssuers().clear();
        JwtTokenValidator validator = new JwtTokenValidator(props, cache);
        String token = buildToken(Instant.now().plusSeconds(60), rsaKey, rsaKey.getKeyID());
        var result = validator.validate(token);
        assertFalse(result.isValid());
        assertTrue(result.getError().startsWith("Unknown"));
    }

    @Test
    void disabledIssuer() throws Exception {
        props.getIssuers().get(0).setEnabled(false);
        JwtTokenValidator validator = new JwtTokenValidator(props, cache);
        String token = buildToken(Instant.now().plusSeconds(60), rsaKey, rsaKey.getKeyID());
        var result = validator.validate(token);
        assertFalse(result.isValid());
    }

    @Test
    void providerDisabled() throws Exception {
        props.getIssuers().get(0).setProvider(SecurityProperties.ProviderType.KEYCLOAK);
        props.setKeycloakEnabled(false);
        JwtTokenValidator validator = new JwtTokenValidator(props, cache);
        String token = buildToken(Instant.now().plusSeconds(60), rsaKey, rsaKey.getKeyID());
        var result = validator.validate(token);
        assertFalse(result.isValid());
        assertEquals("Provider KEYCLOAK disabled", result.getError());
    }

    @Test
    void signatureFailure() throws Exception {
        // Provide a token signed with different key not in cache (kid2)
        RSAKey other = com.jithinnambiar.securitystarter.util.JwtTestUtil.generateRsaJwk("kid2");
        JwtTokenValidator validator = new JwtTokenValidator(props, cache);
        String token = buildToken(Instant.now().plusSeconds(60), other, other.getKeyID());
        var result = validator.validate(token);
        assertFalse(result.isValid());
        assertEquals("Signature verification failed", result.getError());
    }

    @Test
    void malformedToken() {
        JwtTokenValidator validator = new JwtTokenValidator(props, cache);
        var result = validator.validate("not.a.jwt");
        assertFalse(result.isValid());
        assertTrue(result.getError().startsWith("Malformed"));
    }

    @Test
    void emptyToken() {
        JwtTokenValidator validator = new JwtTokenValidator(props, cache);
        var result = validator.validate(" ");
        assertFalse(result.isValid());
        assertEquals("Empty token", result.getError());
    }
}
