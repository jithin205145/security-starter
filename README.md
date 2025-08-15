# Security Starter

Opinionated Spring Boot security starter providing:
- Stateless JWT authentication with pluggable issuers
- Multi-provider support (Generic / Keycloak / Auth0) with per-provider & per-issuer enable switches
- Scope + role extraction (Keycloak realm / client roles, Auth0 permissions)
- Auto-configuration via spring factories (no manual @Enable needed)

## Dependency (consumer project)
Add to your parent / consuming application (after you install/publish to your repository):
```xml
<dependency>
  <groupId>com.jithinnambiar.security</groupId>
  <artifactId>security-starter</artifactId>
  <version>0.0.1-SNAPSHOT</version>
</dependency>
```

Because this is a library JAR, there is intentionally NO Spring Boot main class packaged and the spring-boot-maven-plugin repackage goal is removed.

## Configuration Properties
Top-level switches:
```
platform.security.enabled=true            # Master switch
platform.security.keycloak-enabled=true   # Enable Keycloak-specific role extraction
platform.security.auth0-enabled=true      # Enable Auth0-specific permission extraction
platform.security.fail-on-missing-scope=true  # If true, token missing required scope won't authenticate
platform.security.permit-all-patterns[0]=/actuator/health
platform.security.permit-all-patterns[1]=/actuator/info
platform.security.jwk-cache-ttl-seconds=900
```

Issuer definitions (list):
```
platform.security.issuers[0].id=kc
platform.security.issuers[0].issuer-uri=https://keycloak.example/realms/myrealm
platform.security.issuers[0].jwks-uri=https://keycloak.example/realms/myrealm/protocol/openid-connect/certs
platform.security.issuers[0].audience=account
platform.security.issuers[0].provider=KEYCLOAK
platform.security.issuers[0].client-id=my-api-client
platform.security.issuers[0].required-scopes=profile,email
platform.security.issuers[0].enabled=true

platform.security.issuers[1].id=auth0
platform.security.issuers[1].issuer-uri=https://my-tenant.eu.auth0.com/
platform.security.issuers[1].jwks-uri=https://my-tenant.eu.auth0.com/.well-known/jwks.json
platform.security.issuers[1].audience=https://api.example.com
platform.security.issuers[1].provider=AUTH0
platform.security.issuers[1].auth0-permissions-claim=permissions   # optional override
platform.security.issuers[1].required-scopes=read:users,write:users
platform.security.issuers[1].enabled=true
```
Notes:
- Each issuer can be independently disabled with `enabled=false`.
- A provider-wide disable (`platform.security.keycloak-enabled=false`) short-circuits validation for all issuers of that provider.
- Algorithms default to RS256; override with `allowed-algorithms[0]=RS256` etc.

## How It Works
1. Filter extracts Bearer token, validates signature via Nimbus + cached JWK set.
2. Finds issuer configuration; applies provider & issuer enable checks.
3. Extracts scopes and roles (provider specific logic) and builds a PrincipalContext.
4. Publishes UsernamePasswordAuthenticationToken with ROLE_ and SCOPE_ authorities.

## Extending / Adding Providers
Add enum entry in `SecurityProperties.ProviderType` and extend extraction logic in `JwtService`.

## Minimal Example application.properties
See `src/main/resources/application.properties` for annotated example.

## Testing
A simple context load test is provided. Add integration tests in your consumer app as needed.

## Roadmap / Next Steps
- Optional OAuth2 authorization code support for social login (Google, Facebook)
- Caffeine-based JWK cache implementation
- Metrics (hit/miss) for JWK cache

## License
MIT
