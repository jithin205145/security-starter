package com.jithinnambiar.security.filter;

import com.jithinnambiar.security.SecurityProperties;
import com.jithinnambiar.security.jwt.JwtService;
import com.jithinnambiar.security.jwt.JwtTokenValidator;
import com.jithinnambiar.security.model.PrincipalContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

/**
 * Filter that authenticates incoming requests using a Bearer JWT.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private final JwtService jwtService;
    private final SecurityProperties props;

    public JwtAuthenticationFilter(JwtService jwtService, SecurityProperties props) {
        this.jwtService = jwtService;
        this.props = props;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            String token = header.substring(7).trim();
            JwtTokenValidator.ValidationResult vr = jwtService.validateRaw(token);
            if (!vr.isValid()) {
                log.debug("Invalid JWT: {}", vr.getError());
                if (props.isRejectInvalidTokens()) {
                    sendUnauthorized(response, vr.getError());
                    return;
                }
            } else {
                jwtService.buildContext(vr).ifPresent(ctx -> authenticate(ctx, request));
            }
        }
        chain.doFilter(request, response);
    }

    private void authenticate(PrincipalContext ctx, HttpServletRequest request) {
        if (SecurityContextHolder.getContext().getAuthentication() != null) return;
        // Check required scopes for issuer if configured
        var issuerCfg = props.findIssuer(ctx.getIssuer());
        if (issuerCfg != null && !issuerCfg.getRequiredScopes().isEmpty()) {
            boolean missing = issuerCfg.getRequiredScopes().stream().anyMatch(rs -> !ctx.getScopes().contains(rs));
            if (missing && props.isFailOnMissingScope()) {
                log.debug("Missing required scope(s) for subject {}", ctx.getSubject());
                return; // do not authenticate
            }
        }
        User principal = new User(ctx.getSubject() == null ? "anonymous" : ctx.getSubject(), "N/A",
                ctx.getAuthorities().stream().map(a -> new org.springframework.security.core.authority.SimpleGrantedAuthority(a)).collect(Collectors.toSet()));
        var auth = new UsernamePasswordAuthenticationToken(principal, "N/A", principal.getAuthorities());
        auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    private void sendUnauthorized(HttpServletResponse response, String reason) throws IOException {
        if (response.isCommitted()) return;
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        String safe = reason == null ? "invalid_token" : reason.replace("\"", "\\\"");
        byte[] body = ("{\"error\":\"unauthorized\",\"reason\":\"" + safe + "\"}").getBytes(StandardCharsets.UTF_8);
        response.setContentLength(body.length);
        response.getOutputStream().write(body);
    }
}
