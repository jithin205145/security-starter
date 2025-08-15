package com.jithinnambiar.securitystarter.config;

import com.jithinnambiar.security.SecurityProperties;
import com.jithinnambiar.security.config.SecurityAutoConfiguration;
import com.jithinnambiar.security.model.PrincipalContext;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SecurityAutoConfigurationAdditionalTest {
    @Test
    void toAuthenticationCoversMethod() {
        SecurityAutoConfiguration auto = new SecurityAutoConfiguration();
        PrincipalContext ctx = new PrincipalContext("subj","iss", List.of("read"), List.of("ROLE_USER"), Map.of());
        var auth = auto.toAuthentication(ctx);
        assertEquals(ctx, auth.getPrincipal());
        assertTrue(auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
    }
}

