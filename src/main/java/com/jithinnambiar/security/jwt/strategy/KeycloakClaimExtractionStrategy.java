package com.jithinnambiar.security.jwt.strategy;

import com.jithinnambiar.security.SecurityProperties;
import com.jithinnambiar.security.jwt.JwtService;
import com.nimbusds.jwt.JWTClaimsSet;

import java.util.*;

/** Extract Keycloak realm and client roles plus generic scopes via Generic strategy. */
public class KeycloakClaimExtractionStrategy implements JwtService.ClaimExtractionStrategy {
    private final GenericClaimExtractionStrategy generic = new GenericClaimExtractionStrategy();
    @Override public boolean supports(SecurityProperties.ProviderType providerType) { return providerType == SecurityProperties.ProviderType.KEYCLOAK; }
    @Override public Collection<String> extractScopes(JWTClaimsSet claims, SecurityProperties.IssuerProperties issuerCfg) { return generic.extractScopes(claims, issuerCfg); }
    @Override public Collection<String> extractRoles(JWTClaimsSet claims, SecurityProperties.IssuerProperties issuerCfg) {
        Set<String> roles = new LinkedHashSet<>();
        Object realmAccess = claims.getClaim("realm_access");
        if (realmAccess instanceof Map<?,?> m) {
            Object rr = m.get("roles");
            if (rr instanceof Collection<?> c) c.stream().map(Object::toString).forEach(roles::add);
        }
        Object resourceAccess = claims.getClaim("resource_access");
        if (resourceAccess instanceof Map<?,?> m) {
            if (issuerCfg.getClientId() != null && m.get(issuerCfg.getClientId()) instanceof Map<?,?> client) {
                Object cr = client.get("roles");
                if (cr instanceof Collection<?> c) c.stream().map(Object::toString).forEach(roles::add);
            }
        }
        return roles;
    }
}

