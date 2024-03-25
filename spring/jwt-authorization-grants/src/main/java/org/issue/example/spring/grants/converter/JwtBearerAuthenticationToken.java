package org.issue.example.spring.grants.converter;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.Transient;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.*;

/**
 * 自定义”urn:ietf:params:oauth:grant-type:jwt-bearer“Token
 */
@Transient
public class JwtBearerAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    private final String assertion;


    public JwtBearerAuthenticationToken(Authentication clientPrincipal,
                                        @Nullable String assertion, @Nullable Map<String, Object> additionalParameters) {
        super(AuthorizationGrantType.JWT_BEARER, clientPrincipal, additionalParameters);
        this.assertion = assertion;
    }

    @Override
    public Object getCredentials() {
        return this.assertion;
    }
}