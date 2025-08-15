package com.jithinnambiar.security.jwt;

import com.jithinnambiar.security.SecurityProperties;
import com.jithinnambiar.security.model.PrincipalContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.util.*;

/**
 * Builds a PrincipalContext from a raw JWT using validation rules.
 */
public class JwtService {
    private final JwtTokenValidator validator;
    private final List<ClaimExtractionStrategy> strategies;
    private final SecurityProperties props;

    public JwtService(JwtTokenValidator validator, List<ClaimExtractionStrategy> strategies, SecurityProperties props) {
        this.validator = validator;
        this.strategies = strategies;
        this.props = props;
    }

    public Optional<PrincipalContext> parse(String rawToken) {
        JwtTokenValidator.ValidationResult result = validator.validate(rawToken);
        if (!result.isValid()) return Optional.empty();
        SignedJWT jwt = result.getJwt();
        try {
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            var issuer = result.getIssuer();
            Set<String> scopes = new LinkedHashSet<>();
            Set<String> roles = new LinkedHashSet<>();
            for (ClaimExtractionStrategy s : strategies) {
                if (s.supports(issuer.getProvider())) {
                    scopes.addAll(s.extractScopes(claims, issuer));
                    roles.addAll(s.extractRoles(claims, issuer));
                }
            }
            PrincipalContext ctx = new PrincipalContext(
                    claims.getSubject(),
                    issuer.getIssuerUri(),
                    scopes,
                    roles,
                    claims.getClaims()
            );
            return Optional.of(ctx);
        } catch (ParseException e) {
            return Optional.empty();
        }
    }

    public JwtTokenValidator.ValidationResult validateRaw(String rawToken){ return validator.validate(rawToken); }
    public Optional<PrincipalContext> buildContext(JwtTokenValidator.ValidationResult result){
        if(result==null || !result.isValid()) return Optional.empty();
        try {
            var claims = result.getJwt().getJWTClaimsSet();
            var issuer = result.getIssuer();
            Set<String> scopes = new LinkedHashSet<>();
            Set<String> roles = new LinkedHashSet<>();
            for (ClaimExtractionStrategy s : strategies) {
                if (s.supports(issuer.getProvider())) {
                    scopes.addAll(s.extractScopes(claims, issuer));
                    roles.addAll(s.extractRoles(claims, issuer));
                }
            }
            return Optional.of(new PrincipalContext(claims.getSubject(), issuer.getIssuerUri(), scopes, roles, claims.getClaims()));
        } catch (Exception e){ return Optional.empty(); }
    }

    // Strategy SPI
    public interface ClaimExtractionStrategy {
        boolean supports(SecurityProperties.ProviderType providerType);
        Collection<String> extractScopes(JWTClaimsSet claims, SecurityProperties.IssuerProperties issuerCfg);
        Collection<String> extractRoles(JWTClaimsSet claims, SecurityProperties.IssuerProperties issuerCfg);
    }
}
