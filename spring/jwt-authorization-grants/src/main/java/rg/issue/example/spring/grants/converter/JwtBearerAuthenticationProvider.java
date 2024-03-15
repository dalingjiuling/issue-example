package rg.issue.example.spring.grants.converter;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: Mr.Zhao
 * @Description:
 * @Date:Create：in 2024/3/7 17:51
 * @Modified By:
 */
public class JwtBearerAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        JwtBearerAuthenticationToken jwtBearerAuthenticationToken = (JwtBearerAuthenticationToken) authentication;
        Jwt assertion = (Jwt) jwtBearerAuthenticationToken.getCredentials();
        RegisteredClient registeredClient = (RegisteredClient) jwtBearerAuthenticationToken.getPrincipal();

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
}
