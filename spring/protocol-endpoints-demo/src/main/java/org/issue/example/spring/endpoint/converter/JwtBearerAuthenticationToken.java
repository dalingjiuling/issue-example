package org.issue.example.spring.endpoint.converter;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Transient;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.util.SpringAuthorizationServerVersion;
import org.springframework.util.Assert;

import java.util.*;

/**
 * @Author: Mr.Zhao
 * @Description:
 * @Date:Create：in 2024/3/8 14:06
 * @Modified By:
 */
@Transient
public class JwtBearerAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;
    private final ClientAuthenticationMethod clientAuthenticationMethod;
    private final Object credentials;
    private final Map<String, Object> additionalParameters;
    private final Set<String> scopes;
    private final RegisteredClient registeredClient;

    public JwtBearerAuthenticationToken(RegisteredClient registeredClient,
                                        Object credentials, Set<String> scopes, ClientAuthenticationMethod clientAuthenticationMethod,
                                        Map<String, Object> additionalParameters) {
        super(Collections.emptyList());
        Assert.notNull(clientAuthenticationMethod, "clientAuthenticationMethod cannot be null");
        this.registeredClient = registeredClient;
        this.credentials = credentials;
        this.scopes = Collections.unmodifiableSet(
                scopes != null ?
                        new HashSet<>(scopes) :
                        Collections.emptySet());
        this.clientAuthenticationMethod = clientAuthenticationMethod;
        this.additionalParameters = Collections.unmodifiableMap(
                additionalParameters != null ? additionalParameters : Collections.emptyMap());
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return registeredClient;
    }
}