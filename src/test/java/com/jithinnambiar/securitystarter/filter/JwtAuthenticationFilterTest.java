package com.jithinnambiar.securitystarter.filter;

import com.jithinnambiar.security.SecurityProperties;
import com.jithinnambiar.security.filter.JwtAuthenticationFilter;
import com.jithinnambiar.security.jwt.JwkCache;
import com.jithinnambiar.security.jwt.JwtService;
import com.jithinnambiar.security.jwt.JwtTokenValidator;
import com.jithinnambiar.security.jwt.strategy.GenericClaimExtractionStrategy;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JwtAuthenticationFilterTest {
    private SecurityProperties props;
    private RSAKey rsaKey;
    private String issuer;
    private String audience;
    private String jwksUri;
    private JwkCache cache;
    private JwtService service;

    @BeforeEach
    void setup() throws Exception {
        issuer = "https://filter.issuer";
        audience = "api";
        jwksUri = issuer + "/jwks";
        rsaKey = com.jithinnambiar.securitystarter.util.JwtTestUtil.generateRsaJwk("kid-filter");
        props = new SecurityProperties();
        SecurityProperties.IssuerProperties ip = new SecurityProperties.IssuerProperties();
        ip.setIssuerUri(issuer);
        ip.setJwksUri(jwksUri);
        ip.setAudience(audience);
        props.getIssuers().add(ip);
        cache = new JwkCache() {
            private JWKSet set = new JWKSet(rsaKey.toPublicJWK());
            @Override public JWKSet get(String uri) { return uri.equals(jwksUri)?set:null; }
            @Override public void put(String uri, JWKSet jwkSet) { this.set = jwkSet; }
            @Override public void evict(String uri) { this.set = null; }
        };
        JwtTokenValidator validator = new JwtTokenValidator(props, cache);
        service = new JwtService(validator, List.of(new GenericClaimExtractionStrategy()), props);
        SecurityContextHolder.clearContext();
    }

    private String buildToken() throws Exception {
        var gen = com.jithinnambiar.securitystarter.util.JwtTestUtil.buildToken(
                rsaKey,
                issuer,
                audience,
                Instant.now().plusSeconds(120),
                null,
                "subj-filter");
        return gen.token();
    }

    @Test
    void authenticatesValidBearer() throws Exception {
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(service, props);
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("Authorization", "Bearer " + buildToken());
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain();
        filter.doFilter(req, res, chain);
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("subj-filter", SecurityContextHolder.getContext().getAuthentication().getName());
    }

    @Test
    void invalidBearerRejected() throws ServletException, IOException {
        props.setRejectInvalidTokens(true);
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(service, props);
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("Authorization", "Bearer invalid.token.value");
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain();
        filter.doFilter(req, res, chain);
        assertEquals(401, res.getStatus());
        assertTrue(res.getContentAsString().contains("unauthorized"));
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }
}

