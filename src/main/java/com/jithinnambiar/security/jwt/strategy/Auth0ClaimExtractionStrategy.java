package com.jithinnambiar.security.jwt.strategy;

import com.jithinnambiar.security.SecurityProperties;
import com.jithinnambiar.security.jwt.JwtService;
import com.nimbusds.jwt.JWTClaimsSet;

import java.util.*;

/** Extract Auth0 permissions as roles plus generic scopes. */
public class Auth0ClaimExtractionStrategy implements JwtService.ClaimExtractionStrategy {
    private final GenericClaimExtractionStrategy generic = new GenericClaimExtractionStrategy();
    @Override public boolean supports(SecurityProperties.ProviderType providerType) { return providerType == SecurityProperties.ProviderType.AUTH0; }
    @Override public Collection<String> extractScopes(JWTClaimsSet claims, SecurityProperties.IssuerProperties issuerCfg) { return generic.extractScopes(claims, issuerCfg); }
    @Override public Collection<String> extractRoles(JWTClaimsSet claims, SecurityProperties.IssuerProperties issuerCfg) {
        Set<String> roles = new LinkedHashSet<>();
        String claimName = issuerCfg.getAuth0PermissionsClaim() != null ? issuerCfg.getAuth0PermissionsClaim() : "permissions";
        Object perms = claims.getClaim(claimName);
        if (perms instanceof Collection<?> c) c.stream().map(Object::toString).forEach(roles::add);
        return roles;
    }
}

