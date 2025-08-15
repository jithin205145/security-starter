package com.jithinnambiar.security.config;


import com.jithinnambiar.security.SecurityProperties;
import com.jithinnambiar.security.jwt.InMemoryJwkCache;
import com.jithinnambiar.security.jwt.JwkCache;
import com.jithinnambiar.security.jwt.JwtTokenValidator;
import com.jithinnambiar.security.jwt.JwtService;
import com.jithinnambiar.security.filter.JwtAuthenticationFilter;
import com.jithinnambiar.security.model.PrincipalContext;
import com.jithinnambiar.security.jwt.strategy.GenericClaimExtractionStrategy;
import com.jithinnambiar.security.jwt.strategy.KeycloakClaimExtractionStrategy;
import com.jithinnambiar.security.jwt.strategy.Auth0ClaimExtractionStrategy;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.stream.Collectors;

@AutoConfiguration
@EnableConfigurationProperties(SecurityProperties.class)
@ConditionalOnClass({HttpSecurity.class})
@ConditionalOnProperty(prefix = SecurityProperties.PREFIX, name = "enabled", havingValue = "true", matchIfMissing = true)
public class SecurityAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(SecurityAutoConfiguration.class);

    @Bean
    @ConditionalOnMissingBean
    public JwkCache jwkCache(SecurityProperties props) {
        return new InMemoryJwkCache(props.getJwkCacheTtlSeconds());
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtTokenValidator jwtTokenValidator(SecurityProperties props, JwkCache cache) {
        return new JwtTokenValidator(props, cache);
    }

    @Bean @ConditionalOnMissingBean
    public GenericClaimExtractionStrategy genericClaimExtractionStrategy(){ return new GenericClaimExtractionStrategy(); }
    @Bean @ConditionalOnMissingBean
    public KeycloakClaimExtractionStrategy keycloakClaimExtractionStrategy(){ return new KeycloakClaimExtractionStrategy(); }
    @Bean @ConditionalOnMissingBean
    public Auth0ClaimExtractionStrategy auth0ClaimExtractionStrategy(){ return new Auth0ClaimExtractionStrategy(); }

    @Bean
    @ConditionalOnMissingBean
    public JwtService jwtService(JwtTokenValidator validator, List<com.jithinnambiar.security.jwt.JwtService.ClaimExtractionStrategy> strategies, SecurityProperties props) {
        return new JwtService(validator, strategies, props);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtService jwtService, SecurityProperties props) {
        return new JwtAuthenticationFilter(jwtService, props);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   JwtAuthenticationFilter jwtAuthenticationFilter,
                                                   SecurityProperties props) throws Exception {
        // Basic defaults; consumer can override by defining its own SecurityFilterChain bean
        http.csrf(csrf -> csrf.disable());
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers(props.permitAllPatternsArray()).permitAll()
                .anyRequest().authenticated()
        );
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        http.httpBasic(Customizer.withDefaults());
        log.info("Security starter JWT filter registered.");
        return http.build();
    }

    /**
     * Helper to build Authentication from principal context (not currently exposed as a bean).
     */
    public AbstractAuthenticationToken toAuthentication(PrincipalContext context) {
        return new UsernamePasswordAuthenticationToken(
                context,
                "N/A",
                context.getAuthorities().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())
        );
    }
}