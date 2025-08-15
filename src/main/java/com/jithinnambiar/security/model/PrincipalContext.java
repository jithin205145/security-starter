package com.jithinnambiar.security.model;

import java.util.*;

/**
 * Represents the authenticated principal extracted from a JWT.
 */
public class PrincipalContext {
    private final String subject;
    private final String issuer;
    private final Set<String> scopes;
    private final Set<String> roles;
    private final Map<String, Object> claims;

    public PrincipalContext(String subject, String issuer, Collection<String> scopes, Collection<String> roles, Map<String,Object> claims) {
        this.subject = subject;
        this.issuer = issuer;
        this.scopes = scopes == null ? Set.of() : Set.copyOf(scopes);
        this.roles = roles == null ? Set.of() : Set.copyOf(roles);
        this.claims = claims == null ? Map.of() : Map.copyOf(claims);
    }

    public String getSubject() { return subject; }
    public String getIssuer() { return issuer; }
    public Set<String> getScopes() { return scopes; }
    public Set<String> getRoles() { return roles; }
    public Map<String, Object> getClaims() { return claims; }

    public Collection<String> getAuthorities() {
        // Combine scopes and roles for Spring Security authorities (prefix roles with ROLE_)
        Set<String> auths = new LinkedHashSet<>();
        roles.forEach(r -> auths.add(r.startsWith("ROLE_") ? r : "ROLE_" + r));
        scopes.forEach(s -> auths.add("SCOPE_" + s));
        return auths;
    }

    public boolean hasScope(String scope) { return scopes.contains(scope); }
    public boolean hasRole(String role) { return roles.contains(role) || roles.contains(role.startsWith("ROLE_") ? role.substring(5) : "ROLE_" + role); }
}
