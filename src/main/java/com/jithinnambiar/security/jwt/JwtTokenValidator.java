package com.jithinnambiar.security.jwt;

import com.jithinnambiar.security.SecurityProperties;
import com.jithinnambiar.security.SecurityProperties.IssuerProperties;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;

import java.net.URL;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Validates and verifies a JWT using configured issuers &amp; JWK cache.
 */
public class JwtTokenValidator {
    private final SecurityProperties props;
    private final JwkCache cache;

    public JwtTokenValidator(SecurityProperties props, JwkCache cache) {
        this.props = props;
        this.cache = cache;
    }

    public ValidationResult validate(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return ValidationResult.invalid("Empty token");
        }
        SignedJWT jwt;
        try { jwt = SignedJWT.parse(rawToken); } catch (ParseException e) { return ValidationResult.invalid("Malformed JWT: " + e.getMessage()); }
        com.nimbusds.jwt.JWTClaimsSet cs;
        try { cs = jwt.getJWTClaimsSet(); } catch (ParseException e) { return ValidationResult.invalid("Cannot parse claims: " + e.getMessage()); }
        return internalValidate(jwt, cs);
    }

    private ValidationResult internalValidate(SignedJWT jwt, com.nimbusds.jwt.JWTClaimsSet claimsSet) {
        String issuer = claimsSet.getIssuer();
        IssuerProperties issuerConfig = props.findIssuer(issuer);
        if (issuerConfig == null || !issuerConfig.isEnabled()) {
            return ValidationResult.invalid("Unknown or disabled issuer: " + issuer);
        }
        // Global provider switches
        switch (issuerConfig.getProvider()) {
            case KEYCLOAK -> { if (!props.isKeycloakEnabled()) return ValidationResult.invalid("Provider KEYCLOAK disabled"); }
            case AUTH0 -> { if (!props.isAuth0Enabled()) return ValidationResult.invalid("Provider AUTH0 disabled"); }
            default -> {}
        }
        if (!timeValid(claimsSet.getExpirationTime(), claimsSet.getNotBeforeTime(), issuerConfig.getClockSkewSeconds())) {
            return ValidationResult.invalid("Token expired or not yet valid");
        }
        if (issuerConfig.getAudience() != null) {
            List<String> aud = claimsSet.getAudience();
            if (aud == null || aud.stream().noneMatch(a -> Objects.equals(a, issuerConfig.getAudience()))) {
                return ValidationResult.invalid("Audience mismatch");
            }
        }
        if (!verifySignature(jwt, issuerConfig)) {
            return ValidationResult.invalid("Signature verification failed");
        }
        return ValidationResult.valid(jwt, issuerConfig);
    }

    private boolean timeValid(Date exp, Date nbf, long skewSeconds) {
        Instant now = Instant.now();
        if (exp != null && now.isAfter(exp.toInstant().plusSeconds(skewSeconds))) return false;
        if (nbf != null && now.isBefore(nbf.toInstant().minusSeconds(skewSeconds))) return false;
        return true;
    }

    private boolean verifySignature(SignedJWT jwt, IssuerProperties issuerConfig) {
        JWSHeader header = jwt.getHeader();
        if (header == null) return false;
        if (!issuerConfig.getAllowedAlgorithms().contains(header.getAlgorithm().getName())) return false;
        String kid = header.getKeyID();
        try {
            JWKSet jwkSet = loadJwkSet(issuerConfig);
            if (jwkSet == null) return false;
            Optional<JWK> jwkOpt = jwkSet.getKeys().stream()
                    .filter(j -> kid == null || kid.equals(j.getKeyID()))
                    .filter(j -> j.getAlgorithm() == null || j.getAlgorithm().equals(header.getAlgorithm()))
                    .findFirst();
            if (jwkOpt.isEmpty()) return false;
            JWK jwk = jwkOpt.get();
            if (!JWSAlgorithm.parse(jwk.getAlgorithm() == null ? header.getAlgorithm().getName() : jwk.getAlgorithm().getName()).equals(header.getAlgorithm())) return false;
            if (!(jwk instanceof com.nimbusds.jose.jwk.RSAKey rsaKey)) return false; // only RSA supported currently
            return jwt.verify(new RSASSAVerifier(rsaKey));
        } catch (Exception e) { return false; }
    }

    private JWKSet loadJwkSet(IssuerProperties issuerConfig) {
        String uri = issuerConfig.getJwksUri();
        if (uri == null) return null;
        JWKSet cached = cache.get(uri);
        if (cached != null) return cached;
        try { JWKSet fetched = JWKSet.load(new URL(uri)); cache.put(uri, fetched); return fetched; } catch (Exception e) { return null; }
    }

    public static class ValidationResult {
        private final boolean valid; private final String error; private final SignedJWT jwt; private final IssuerProperties issuer;
        private ValidationResult(boolean valid, String error, SignedJWT jwt, IssuerProperties issuer) { this.valid = valid; this.error = error; this.jwt = jwt; this.issuer = issuer; }
        public static ValidationResult invalid(String error) { return new ValidationResult(false, error, null, null); }
        public static ValidationResult valid(SignedJWT jwt, IssuerProperties issuer) { return new ValidationResult(true, null, jwt, issuer); }
        public boolean isValid() { return valid; } public String getError() { return error; } public SignedJWT getJwt() { return jwt; } public IssuerProperties getIssuer() { return issuer; }
    }
}
