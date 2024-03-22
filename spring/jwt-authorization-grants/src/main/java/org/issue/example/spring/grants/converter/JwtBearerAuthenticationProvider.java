package org.issue.example.spring.grants.converter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.JwtClientAssertionDecoderFactory;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.CollectionUtils;
;
import java.time.Instant;
import java.util.*;

/**
 * 自定义”urn:ietf:params:oauth:grant-type:jwt-bearer“Provider
 */
public class JwtBearerAuthenticationProvider implements AuthenticationProvider {
    private final Log logger = LogFactory.getLog(getClass());
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7523#section-2.1";
    RegisteredClientRepository registeredClientRepository;
    private JwtDecoderFactory<RegisteredClient> jwtDecoderFactory;
    OAuth2AuthorizationService authorizationService;

    public JwtBearerAuthenticationProvider(HttpSecurity httpSecurity) {
        this.registeredClientRepository = httpSecurity.getSharedObject(RegisteredClientRepository.class);
        this.authorizationService = httpSecurity.getSharedObject(OAuth2AuthorizationService.class);
        this.jwtDecoderFactory = new JwtClientAssertionDecoderFactory();
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        JwtBearerAuthenticationToken authenticationToken =
                (JwtBearerAuthenticationToken) authentication;

        if (!AuthorizationGrantType.JWT_BEARER.equals(authenticationToken.getAuthorizationGrantType())) {
            return null;
        }

        String clientId = authenticationToken.getPrincipal().toString();
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throwInvalidClient(OAuth2ParameterNames.CLIENT_ID);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Retrieved registered client");
        }

        if (authenticationToken.getCredentials() == null) {
            throwInvalidClient("credentials");
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
        if (!expiresAt.isBefore(now)) {
            // assertion过期了
            this.logger.trace("Validated assertion timeout");
            throwInvalidClient(OAuth2ParameterNames.ASSERTION);
        }

        String[] scopes = jwtAssertion.getClaim(OAuth2ParameterNames.SCOPE);
        List<String> requestedScopes = new ArrayList<>();
        if (null != scopes) {
            requestedScopes.addAll(Arrays.asList(scopes));
        }

        // assertion的scope范围必须等于或小于已注册客户端信息的scope
        if (!CollectionUtils.isEmpty(requestedScopes)) {
            for (String requestedScope : requestedScopes) {
                if (!registeredClient.getScopes().contains(requestedScope)) {
                    throwInvalidClient(OAuth2ParameterNames.SCOPE);
                }
            }
        }

        // 参考，DelegatingOAuth2TokenGenerator如何生成access_token
        // TODO 需要把生成access_token放到内存或数据库等存储库中


        // 需要根据assertion生成access_token，或者刷新access_token
        Jwt assertion = (Jwt) authenticationToken.getCredentials();

        String access_token = assertion.getTokenValue();
        Instant expires_in = assertion.getExpiresAt();
        String token_type = "Bearer";

        // token返回：参考https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.3
        Map<String, Object> map = new HashMap<>();
        map.put("access_token", access_token);
        map.put("token_type", token_type);
        map.put("expires_in", expires_in);

        ClientAuthenticationMethod clientAuthenticationMethod =
                registeredClient.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm() instanceof SignatureAlgorithm ?
                        ClientAuthenticationMethod.PRIVATE_KEY_JWT :
                        ClientAuthenticationMethod.CLIENT_SECRET_JWT;

        return new OAuth2ClientAuthenticationToken(registeredClient, clientAuthenticationMethod, assertion);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtBearerAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * 生成 access_token，规则：授权服务器不应发布生存期超过assertion有效期的访问令牌（access_token）。这通常意味着不会在响应assertion授权请求时发布刷新令牌（refresh_token），而发布访问令牌的生命周期将相当短。客户端可以通过使用相同的assertion（如果仍然有效）或使用新的assertion请求新的访问令牌来刷新过期的访问令牌。
     *
     * @param registeredClient 客户端信息
     * @param expiresAt        assertion过期时间
     */
    private static void generate(RegisteredClient registeredClient, Instant expiresAt) {


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
