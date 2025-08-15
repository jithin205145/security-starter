package com.jithinnambiar.securitystarter.model;

import com.jithinnambiar.security.model.PrincipalContext;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PrincipalContextTest {
    @Test
    void authoritiesAndRoleScopePrefixes() {
        PrincipalContext ctx = new PrincipalContext("sub","iss", List.of("read","write"), List.of("ADMIN","ROLE_USER"), Map.of("k","v"));
        var auths = ctx.getAuthorities();
        assertTrue(auths.contains("ROLE_ADMIN"));
        assertTrue(auths.contains("ROLE_USER"));
        assertTrue(auths.contains("SCOPE_read"));
        assertTrue(auths.contains("SCOPE_write"));
        assertTrue(ctx.hasRole("ADMIN"));
        assertTrue(ctx.hasRole("ROLE_ADMIN"));
        assertTrue(ctx.hasScope("read"));
        // cover getters
        assertTrue(ctx.getRoles().contains("ADMIN"));
        assertEquals("v", ctx.getClaims().get("k"));
    }
}
