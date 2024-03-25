package org.issue.example.spring.grants.converter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.JwtClientAssertionDecoderFactory;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.CollectionUtils;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 自定义”urn:ietf:params:oauth:grant-type:jwt-bearer“Provider
 * <a href="https://datatracker.ietf.org/doc/html/rfc7523#section-2.2">参考<a/>
 */
public class JwtBearerAuthenticationProvider implements AuthenticationProvider {
    private final Log logger = LogFactory.getLog(getClass());
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7523#section-2.1";
    private JwtDecoderFactory<RegisteredClient> jwtDecoderFactory;
    OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    public JwtBearerAuthenticationProvider(HttpSecurity httpSecurity) {
        this.authorizationService = httpSecurity.getSharedObject(OAuth2AuthorizationService.class);
        this.jwtDecoderFactory = new JwtClientAssertionDecoderFactory();
        this.tokenGenerator = httpSecurity.getSharedObject(OAuth2TokenGenerator.class);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        JwtBearerAuthenticationToken authenticationToken =
                (JwtBearerAuthenticationToken) authentication;

        OAuth2ClientAuthenticationToken clientPrincipal =
                getAuthenticatedClientElseThrowInvalidClient(authenticationToken);

        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Retrieved registered client");
        }

        if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.JWT_BEARER)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        Jwt jwtAssertion = null;
        JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(registeredClient);
        try {
            jwtAssertion = jwtDecoder.decode(authenticationToken.getCredentials().toString());
        } catch (JwtException ex) {
            throwInvalidClient(OAuth2ParameterNames.ASSERTION, ex);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Validated client authentication parameters");
        }

        // 检验assertion的生命周期是否超时
        Instant expiresAt = jwtAssertion.getExpiresAt();
        Instant now = Instant.now();
        if (expiresAt.isBefore(now)) {
            // assertion过期了
            this.logger.trace("Validated assertion timeout");
            throwInvalidClient(OAuth2ParameterNames.ASSERTION);
        }

        List<String> scopes = jwtAssertion.getClaim(OAuth2ParameterNames.SCOPE);
        Set<String> authorizedScopes = Collections.emptySet();
        if (null != scopes) {
            authorizedScopes = scopes.stream().collect(Collectors.toSet());
        }

        // assertion的scope范围必须等于或小于已注册客户端信息的scope
        if (!CollectionUtils.isEmpty(authorizedScopes)) {
            for (String requestedScope : authorizedScopes) {
                if (!registeredClient.getScopes().contains(requestedScope)) {
                    throwInvalidClient(OAuth2ParameterNames.SCOPE);
                }
            }
        }

        // @formatter:off
        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(clientPrincipal)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(authorizedScopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
                .authorizationGrant(authenticationToken)
                .build();
        // @formatter:on

        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the access token.", ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Generated access token");
        }

        // 授权服务器不应发布生存期超过assertion有效期的访问令牌（access_token）
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
                expiresAt, tokenContext.getAuthorizedScopes());

        // @formatter:off
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(clientPrincipal.getName())
                .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
                .authorizedScopes(authorizedScopes);
        // @formatter:on
        if (generatedAccessToken instanceof ClaimAccessor) {
            authorizationBuilder.token(accessToken, (metadata) ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, ((ClaimAccessor) generatedAccessToken).getClaims()));
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        OAuth2Authorization authorization = authorizationBuilder.build();

        this.authorizationService.save(authorization);

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Saved authorization");
            // This log is kept separate for consistency with other providers
            this.logger.trace("Authenticated token request");
        }

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtBearerAuthenticationToken.class.isAssignableFrom(authentication);
    }

    static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }

    private static void throwInvalidClient(String parameterName) {
        throwInvalidClient(parameterName, null);
    }

    private static void throwInvalidClient(String parameterName, Throwable cause) {
        OAuth2Error error = new OAuth2Error(
                OAuth2ErrorCodes.INVALID_CLIENT,
                "Client authentication failed: " + parameterName,
                ERROR_URI
        );
        throw new OAuth2AuthenticationException(error, error.toString(), cause);
    }
}
