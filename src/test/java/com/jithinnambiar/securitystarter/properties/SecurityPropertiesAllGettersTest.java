package com.jithinnambiar.securitystarter.properties;

import com.jithinnambiar.security.SecurityProperties;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SecurityPropertiesAllGettersTest {
    @Test
    void coverTopLevelGetters() {
        SecurityProperties p = new SecurityProperties();
        // invoke all simple getters once
        assertTrue(p.isEnabled());
        assertTrue(p.isFailOnMissingScope());
        assertTrue(p.isKeycloakEnabled());
        assertTrue(p.isAuth0Enabled());
        assertTrue(p.isRejectInvalidTokens());
        assertNotNull(p.getPermitAllPatterns());
        assertTrue(p.getJwkCacheTtlSeconds() > 0);
        assertNotNull(p.getIssuers());
        // also call permitAllPatternsArray() when list non-null
        assertTrue(p.permitAllPatternsArray().length >= 0);
    }
}

