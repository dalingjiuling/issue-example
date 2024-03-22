package org.issue.example.spring.grants.converter;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Transient;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.util.SpringAuthorizationServerVersion;
import org.springframework.util.Assert;

import java.util.*;

/**
 * 自定义”urn:ietf:params:oauth:grant-type:jwt-bearer“Token
 */
@Transient
public class JwtBearerAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;
    private final Object credentials;
    private final Map<String, Object> additionalParameters;
    private final String clientId;
    private final AuthorizationGrantType authorizationGrantType;

    public JwtBearerAuthenticationToken(String clientId,
                                        AuthorizationGrantType authorizationGrantType,
                                        Object credentials,
                                        Map<String, Object> additionalParameters) {
        super(Collections.emptyList());
        Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");
        this.clientId = clientId;
        this.authorizationGrantType = authorizationGrantType;
        this.credentials = credentials;
        this.additionalParameters = Collections.unmodifiableMap(
                additionalParameters != null ? additionalParameters : Collections.emptyMap());
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.clientId;
    }

    public AuthorizationGrantType getAuthorizationGrantType() {
        return authorizationGrantType;
    }
}