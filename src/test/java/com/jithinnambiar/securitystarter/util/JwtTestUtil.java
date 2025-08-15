package com.jithinnambiar.securitystarter.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public final class JwtTestUtil {
    private JwtTestUtil() {}

    public record GeneratedToken(String token, RSAKey rsaKey, JWTClaimsSet claims) {}

    public static RSAKey generateRsaJwk(String kid) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        return new RSAKey.Builder((java.security.interfaces.RSAPublicKey) kp.getPublic())
                .privateKey(kp.getPrivate())
                .keyID(kid)
                .algorithm(JWSAlgorithm.RS256)
                .build();
    }

    public static GeneratedToken buildToken(RSAKey key, String issuer, String audience, Instant exp, Instant nbf, String subject) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .expirationTime(Date.from(exp))
                .notBeforeTime(nbf==null?null:Date.from(nbf))
                .issueTime(Date.from(Instant.now()))
                .subject(subject)
                .claim("scope", "read write")
                .claim("roles", List.of("ADMIN","user"))
                .jwtID(UUID.randomUUID().toString())
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new RSASSASigner(key));
        return new GeneratedToken(jwt.serialize(), key, claims);
    }
}

