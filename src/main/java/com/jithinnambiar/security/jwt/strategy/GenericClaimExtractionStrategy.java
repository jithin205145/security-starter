package com.jithinnambiar.security.jwt.strategy;

import com.jithinnambiar.security.SecurityProperties;
import com.jithinnambiar.security.jwt.JwtService;
import com.nimbusds.jwt.JWTClaimsSet;

import java.util.*;

/** Generic extraction: scope/scope list &amp; roles list. */
public class GenericClaimExtractionStrategy implements JwtService.ClaimExtractionStrategy {
    @Override
    public boolean supports(SecurityProperties.ProviderType providerType) { return true; }

    @Override
    public Collection<String> extractScopes(JWTClaimsSet claims, SecurityProperties.IssuerProperties issuerCfg) {
        Set<String> scopes = new LinkedHashSet<>();
        Object scope = claims.getClaim("scope");
        if (scope instanceof String s) Arrays.stream(s.split(" ")).filter(x->!x.isBlank()).forEach(scopes::add);
        Object scp = claims.getClaim("scp");
        if (scp instanceof Collection<?> c) c.stream().map(Object::toString).forEach(scopes::add);
        Object perms = claims.getClaim("permissions");
        if (perms instanceof Collection<?> c) c.stream().map(Object::toString).forEach(scopes::add);
        return scopes;
    }

    @Override
    public Collection<String> extractRoles(JWTClaimsSet claims, SecurityProperties.IssuerProperties issuerCfg) {
        Set<String> roles = new LinkedHashSet<>();
        Object r = claims.getClaim("roles");
        if (r instanceof Collection<?> c) c.stream().map(Object::toString).forEach(roles::add);
        return roles;
    }
}
