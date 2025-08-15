package com.jithinnambiar.securitystarter.jwt;

import com.jithinnambiar.security.SecurityProperties;
import com.jithinnambiar.security.jwt.*;
import com.jithinnambiar.security.jwt.strategy.*;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceAdditionalTest {
    private RSAKey rsaKey(String kid) throws Exception {
        return com.jithinnambiar.securitystarter.util.JwtTestUtil.generateRsaJwk(kid);
    }

    private String token(RSAKey key, String iss, String aud, Map<String,Object> claims) throws Exception {
        JWTClaimsSet.Builder b = new JWTClaimsSet.Builder()
                .issuer(iss)
                .audience(aud)
                .subject("userX")
                .expirationTime(Date.from(Instant.now().plusSeconds(120)))
                .issueTime(new Date());
        claims.forEach(b::claim);
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), b.build());
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    private JwtService service(SecurityProperties props, RSAKey key){
        JwkCache cache = new JwkCache(){
            private final JWKSet set = new JWKSet(key.toPublicJWK());
            @Override public JWKSet get(String u){return set;} @Override public void put(String u,JWKSet s){} @Override public void evict(String u){}
        };
        JwtTokenValidator validator = new JwtTokenValidator(props, cache);
        return new JwtService(validator, List.of(new GenericClaimExtractionStrategy(), new KeycloakClaimExtractionStrategy(), new Auth0ClaimExtractionStrategy()), props);
    }

    @Test
    void parseValidCoversParseMethod() throws Exception {
        SecurityProperties props = new SecurityProperties();
        SecurityProperties.IssuerProperties ip = new SecurityProperties.IssuerProperties();
        String iss = "https://svc.parse"; ip.setIssuerUri(iss); ip.setJwksUri(iss+"/jwks"); ip.setAudience("aud");
        props.getIssuers().add(ip);
        RSAKey key = rsaKey("kid-parse");
        JwtService svc = service(props, key);
        String t = token(key, iss, "aud", Map.of("scope","a b","roles", List.of("R1")));
        assertTrue(svc.parse(t).isPresent());
    }

    @Test
    void buildContextInvalidResultReturnsEmpty() {
        SecurityProperties props = new SecurityProperties();
        SecurityProperties.IssuerProperties ip = new SecurityProperties.IssuerProperties();
        ip.setIssuerUri("https://x"); ip.setJwksUri("https://x/jwks"); ip.setAudience("a");
        props.getIssuers().add(ip);
        RSAKey key; try { key = rsaKey("kid"); } catch (Exception e){ fail(e); return; }
        JwtService svc = service(props, key);
        var invalid = svc.validateRaw("bad.token");
        assertTrue(invalid.getError().startsWith("Malformed"));
        assertTrue(svc.buildContext(invalid).isEmpty());
    }

    @Test
    void strategySupportsAndExtraction() throws Exception {
        var generic = new GenericClaimExtractionStrategy();
        var keycloak = new KeycloakClaimExtractionStrategy();
        var auth0 = new Auth0ClaimExtractionStrategy();
        assertTrue(generic.supports(SecurityProperties.ProviderType.AUTH0));
        assertTrue(keycloak.supports(SecurityProperties.ProviderType.KEYCLOAK));
        assertFalse(keycloak.supports(SecurityProperties.ProviderType.GENERIC));
        assertTrue(auth0.supports(SecurityProperties.ProviderType.AUTH0));
        // Build sample claims
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("scope","s1 s2").claim("permissions", List.of("p1","p2"))
                .claim("realm_access", Map.of("roles", List.of("rr")))
                .claim("resource_access", Map.of("client", Map.of("roles", List.of("cr"))))
                .build();
        SecurityProperties.IssuerProperties issuer = new SecurityProperties.IssuerProperties();
        issuer.setClientId("client"); issuer.setAuth0PermissionsClaim("permissions");
        issuer.setProvider(SecurityProperties.ProviderType.KEYCLOAK);
        assertTrue(keycloak.extractRoles(claims, issuer).contains("rr"));
        issuer.setProvider(SecurityProperties.ProviderType.AUTH0);
        assertTrue(auth0.extractRoles(claims, issuer).contains("p1"));
        issuer.setProvider(SecurityProperties.ProviderType.GENERIC);
        assertTrue(generic.extractScopes(claims, issuer).contains("s1"));
    }

    @Test
    void jwkCacheDefaultStats() {
        JwkCache cache = new JwkCache() { @Override public JWKSet get(String u){return null;} @Override public void put(String u,JWKSet s){} @Override public void evict(String u){} };
        assertEquals(0, cache.stats().hits());
        assertEquals(0, cache.stats().misses());
    }
}

