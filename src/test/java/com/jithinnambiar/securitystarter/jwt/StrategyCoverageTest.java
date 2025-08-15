package com.jithinnambiar.securitystarter.jwt;

import com.jithinnambiar.security.SecurityProperties;
import com.jithinnambiar.security.jwt.strategy.Auth0ClaimExtractionStrategy;
import com.jithinnambiar.security.jwt.strategy.KeycloakClaimExtractionStrategy;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class StrategyCoverageTest {
    @Test
    void coverExtractScopesKeycloakAndAuth0() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("scope", "alpha beta")
                .claim("scp", List.of("gamma"))
                .claim("permissions", List.of("perm1"))
                .build();
        SecurityProperties.IssuerProperties kcIssuer = new SecurityProperties.IssuerProperties();
        kcIssuer.setProvider(SecurityProperties.ProviderType.KEYCLOAK);
        SecurityProperties.IssuerProperties auth0Issuer = new SecurityProperties.IssuerProperties();
        auth0Issuer.setProvider(SecurityProperties.ProviderType.AUTH0);
        auth0Issuer.setAuth0PermissionsClaim("permissions");
        var kc = new KeycloakClaimExtractionStrategy();
        var auth0 = new Auth0ClaimExtractionStrategy();
        assertTrue(kc.supports(SecurityProperties.ProviderType.KEYCLOAK));
        assertEquals(4, kc.extractScopes(claims, kcIssuer).size());
        assertTrue(auth0.supports(SecurityProperties.ProviderType.AUTH0));
        assertEquals(4, auth0.extractScopes(claims, auth0Issuer).size());
    }
}
