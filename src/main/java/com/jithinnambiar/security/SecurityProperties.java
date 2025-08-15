package com.jithinnambiar.security;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Validated
@ConfigurationProperties(prefix = SecurityProperties.PREFIX)
public class SecurityProperties {
    public static final String PREFIX = "platform.security";

    public enum ProviderType { GENERIC, KEYCLOAK, AUTH0, GOOGLE, FACEBOOK }

    private boolean enabled = true;
    private boolean failOnMissingScope = true;
    // Provider master switches
    private boolean keycloakEnabled = true;
    private boolean auth0Enabled = true;
    /** If true, an invalid bearer token immediately results in 401; if false the request proceeds unauthenticated. */
    private boolean rejectInvalidTokens = true;

    /** Global permitAll patterns (e.g., health, metrics). */
    private List<String> permitAllPatterns = List.of(
            "/actuator/health",
            "/actuator/info"
    );
    /** JWK cache TTL seconds (soft expiration). */
    private long jwkCacheTtlSeconds = Duration.ofMinutes(15).getSeconds();
    /** Configured issuers. */
    private List<IssuerProperties> issuers = new ArrayList<>();

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public boolean isFailOnMissingScope() { return failOnMissingScope; }
    public void setFailOnMissingScope(boolean failOnMissingScope) { this.failOnMissingScope = failOnMissingScope; }

    public boolean isKeycloakEnabled() { return keycloakEnabled; }
    public void setKeycloakEnabled(boolean keycloakEnabled) { this.keycloakEnabled = keycloakEnabled; }
    public boolean isAuth0Enabled() { return auth0Enabled; }
    public void setAuth0Enabled(boolean auth0Enabled) { this.auth0Enabled = auth0Enabled; }

    public boolean isRejectInvalidTokens() { return rejectInvalidTokens; }
    public void setRejectInvalidTokens(boolean rejectInvalidTokens) { this.rejectInvalidTokens = rejectInvalidTokens; }

    public List<String> getPermitAllPatterns() { return permitAllPatterns; }
    public void setPermitAllPatterns(List<String> permitAllPatterns) { this.permitAllPatterns = permitAllPatterns; }
    public long getJwkCacheTtlSeconds() { return jwkCacheTtlSeconds; }
    public void setJwkCacheTtlSeconds(long jwkCacheTtlSeconds) { this.jwkCacheTtlSeconds = jwkCacheTtlSeconds; }
    public List<IssuerProperties> getIssuers() { return issuers; }
    public void setIssuers(List<IssuerProperties> issuers) { this.issuers = issuers; }

    public String[] permitAllPatternsArray() {
        return permitAllPatterns == null ? new String[0] : permitAllPatterns.toArray(new String[0]);
    }

    public IssuerProperties findIssuer(String issClaim) {
        if (issClaim == null || issuers.isEmpty()) return null;
        for (IssuerProperties ip : issuers) {
            if (issClaim.equals(ip.getIssuerUri())) return ip;
        }
        return null;
    }

    public static class IssuerProperties {
        private String id;
        @NotBlank(message = "issuerUri must not be blank")
        private String issuerUri;
        @NotBlank(message = "jwksUri must not be blank")
        private String jwksUri;
        private String audience;
        private List<String> allowedAlgorithms = List.of("RS256");
        private List<String> requiredScopes = new ArrayList<>();
        private long clockSkewSeconds = 60;
        private ProviderType provider = ProviderType.GENERIC;
        private String clientId; // Keycloak clientId for resource_access
        private String auth0PermissionsClaim; // Auth0 custom claim override
        private boolean enabled = true;

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getIssuerUri() { return issuerUri; }
        public void setIssuerUri(String issuerUri) { this.issuerUri = issuerUri; }
        public String getJwksUri() { return jwksUri; }
        public void setJwksUri(String jwksUri) { this.jwksUri = jwksUri; }
        public String getAudience() { return audience; }
        public void setAudience(String audience) { this.audience = audience; }
        public List<String> getAllowedAlgorithms() { return allowedAlgorithms; }
        public void setAllowedAlgorithms(List<String> allowedAlgorithms) { this.allowedAlgorithms = allowedAlgorithms; }
        public List<String> getRequiredScopes() { return requiredScopes; }
        public void setRequiredScopes(List<String> requiredScopes) { this.requiredScopes = requiredScopes; }
        public long getClockSkewSeconds() { return clockSkewSeconds; }
        public void setClockSkewSeconds(long clockSkewSeconds) { this.clockSkewSeconds = clockSkewSeconds; }
        public ProviderType getProvider() { return provider; }
        public void setProvider(ProviderType provider) { this.provider = provider; }
        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }
        public String getAuth0PermissionsClaim() { return auth0PermissionsClaim; }
        public void setAuth0PermissionsClaim(String auth0PermissionsClaim) { this.auth0PermissionsClaim = auth0PermissionsClaim; }
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public List<String> immutableScopes() { return requiredScopes == null ? Collections.emptyList() : List.copyOf(requiredScopes); }
    }
}