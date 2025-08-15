package com.jithinnambiar.securitystarter.properties;

import com.jithinnambiar.security.SecurityProperties;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SecurityPropertiesTest {
    @Test
    void gettersSettersAndFindIssuerBranches() {
        SecurityProperties props = new SecurityProperties();
        props.setEnabled(false);
        props.setFailOnMissingScope(false);
        props.setKeycloakEnabled(false);
        props.setAuth0Enabled(false);
        props.setRejectInvalidTokens(false);
        props.setPermitAllPatterns(List.of("/h1","/h2"));
        props.setJwkCacheTtlSeconds(123L);
        SecurityProperties.IssuerProperties ip1 = new SecurityProperties.IssuerProperties();
        ip1.setIssuerUri("https://a");
        ip1.setJwksUri("https://a/jwks");
        SecurityProperties.IssuerProperties ip2 = new SecurityProperties.IssuerProperties();
        ip2.setIssuerUri("https://b");
        ip2.setJwksUri("https://b/jwks");
        props.setIssuers(List.of(ip1, ip2));
        assertFalse(props.isEnabled());
        assertFalse(props.isFailOnMissingScope());
        assertFalse(props.isKeycloakEnabled());
        assertFalse(props.isAuth0Enabled());
        assertFalse(props.isRejectInvalidTokens());
        assertEquals(123L, props.getJwkCacheTtlSeconds());
        assertNotNull(props.findIssuer("https://a"));
        assertNull(props.findIssuer("https://missing"));
        // cover getPermitAllPatterns default list
        assertNotNull(props.getPermitAllPatterns());
        // permitAll null branch
        props.setPermitAllPatterns(null);
        assertEquals(0, props.permitAllPatternsArray().length);
    }

    @Test
    void issuerPropertiesGettersSettersAndImmutableScopes() {
        SecurityProperties.IssuerProperties ip = new SecurityProperties.IssuerProperties();
        ip.setId("id1");
        ip.setIssuerUri("iss");
        ip.setJwksUri("jwks");
        ip.setAudience("aud");
        ip.setAllowedAlgorithms(List.of("RS256","RS512"));
        ip.setRequiredScopes(List.of("s1","s2"));
        ip.setClockSkewSeconds(5); ip.setProvider(SecurityProperties.ProviderType.KEYCLOAK);
        ip.setClientId("client"); ip.setAuth0PermissionsClaim("perm"); ip.setEnabled(false);
        assertEquals("id1", ip.getId());
        assertEquals("iss", ip.getIssuerUri());
        assertEquals("jwks", ip.getJwksUri());
        assertEquals("aud", ip.getAudience());
        assertEquals(2, ip.getAllowedAlgorithms().size());
        assertEquals(2, ip.getRequiredScopes().size());
        assertEquals(5, ip.getClockSkewSeconds());
        assertEquals(SecurityProperties.ProviderType.KEYCLOAK, ip.getProvider());
        assertEquals("client", ip.getClientId());
        assertEquals("perm", ip.getAuth0PermissionsClaim());
        assertFalse(ip.isEnabled());
        assertEquals(2, ip.immutableScopes().size());
        ip.setRequiredScopes(null);
        assertEquals(0, ip.immutableScopes().size());
    }
}
