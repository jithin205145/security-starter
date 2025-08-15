package com.jithinnambiar.securitystarter.filter;

import com.jithinnambiar.security.SecurityProperties;
import com.jithinnambiar.security.filter.JwtAuthenticationFilter;
import com.jithinnambiar.security.jwt.JwkCache;
import com.jithinnambiar.security.jwt.JwtService;
import com.jithinnambiar.security.jwt.JwtTokenValidator;
import com.jithinnambiar.security.jwt.strategy.GenericClaimExtractionStrategy;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class JwtAuthenticationFilterAdditionalTest {
    private RSAKey key;
    private SecurityProperties props;
    private String issuer;
    private String audience;
    private String jwks;
    private JwtService service;

    @BeforeEach
    void setup() throws Exception {
        issuer = "https://filter.extra";
        audience = "aud";
        jwks = issuer+"/jwks";
        key = com.jithinnambiar.securitystarter.util.JwtTestUtil.generateRsaJwk("kid-extra");
        props = new SecurityProperties();
        SecurityProperties.IssuerProperties ip = new SecurityProperties.IssuerProperties();
        ip.setIssuerUri(issuer); ip.setJwksUri(jwks); ip.setAudience(audience);
        ip.setRequiredScopes(List.of("admin")); // require admin scope
        props.getIssuers().add(ip);
        JwkCache cache = new JwkCache(){
            private final JWKSet set = new JWKSet(key.toPublicJWK());
            @Override public JWKSet get(String u){ return set; }
            @Override public void put(String u,JWKSet s){}
            @Override public void evict(String u){}
        };
        JwtTokenValidator validator = new JwtTokenValidator(props, cache);
        service = new JwtService(validator, List.of(new GenericClaimExtractionStrategy()), props);
        SecurityContextHolder.clearContext();
    }

    private String tokenWithScope(String scope) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .subject("u1")
                .expirationTime(Date.from(Instant.now().plusSeconds(120)))
                .issueTime(new Date())
                .claim("scope", scope)
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    @Test
    void missingRequiredScopeSkipsAuthentication() throws Exception {
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(service, props);
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("Authorization","Bearer "+ tokenWithScope("read")); // no admin scope
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(req, res, new MockFilterChain());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void invalidTokenProceedWhenRejectDisabled() throws Exception {
        props.setRejectInvalidTokens(false);
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(service, props);
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("Authorization","Bearer invalid.jwt.token");
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(req, res, new MockFilterChain());
        assertEquals(200, res.getStatus());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }
}

