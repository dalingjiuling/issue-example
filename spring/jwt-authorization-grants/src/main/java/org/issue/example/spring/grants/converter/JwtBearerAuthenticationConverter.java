package org.issue.example.spring.grants.converter;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.impl.RSASSA;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.*;
import java.text.ParseException;
import java.util.*;

/**
 * 自定义Using JWTs as Authorization Grants。
 * <a href="https://blog.csdn.net/qq_31772441/article/details/127099119">参考private_key_jwt</a>
 * <a href="https://datatracker.ietf.org/doc/html/rfc7523#section-2.1">参考Using JWTs as Authorization Grants</a>
 * 参考{@link com.nimbusds.jose.proc.JWSAlgorithmFamilyJWSKeySelector}
 */
public class JwtBearerAuthenticationConverter implements AuthenticationConverter {
    private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7523#section-2.1";
    private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken(
            "anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    private final RegisteredClientRepository registeredClientRepository;
    private HttpSecurity httpSecurity;
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private final String JWK_SET_URL = "jwk-set-url";

    public JwtBearerAuthenticationConverter(HttpSecurity httpSecurity) {
        this.httpSecurity = httpSecurity;
        this.registeredClientRepository = httpSecurity.getSharedObject(RegisteredClientRepository.class);
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        MultiValueMap<String, String> parameters = getFormParameters(request);

        // grant_type (REQUIRED)
        String grantType = parameters.getFirst(OAuth2ParameterNames.GRANT_TYPE);
        if (!AuthorizationGrantType.JWT_BEARER.getValue().equals(grantType)) {
            return null;
        }

        // assertion (REQUIRED)
        String assertion = parameters.getFirst(OAuth2ParameterNames.ASSERTION);
        if (!StringUtils.hasText(assertion)) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.ASSERTION);
        }

        String[] parts = assertion.split("\\.");
        if (3 != parts.length) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.ASSERTION);
        }

        Base64URL headerBase64 = Base64URL.from(parts[0]);
        Base64URL payloadBase64 = Base64URL.from(parts[1]);
        Base64URL signatureBase64 = Base64URL.from(parts[2]);

        JWSHeader jwsHeader = null;
        try {
            jwsHeader = JWSHeader.parse(headerBase64);
        } catch (ParseException e) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.ASSERTION);
        }
        JWSAlgorithm jwsAlgorithm = jwsHeader.getAlgorithm();

        JWTClaimsSet jwtClaimsSet = null;
        try {
            jwtClaimsSet = JWTClaimsSet.parse(payloadBase64.decodeToString());
        } catch (ParseException e) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.ASSERTION);
        }

        String Subject = jwtClaimsSet.getSubject();
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(Subject);
        if (null == registeredClient) {
            throwError(OAuth2ErrorCodes.INVALID_CLIENT, OAuth2ParameterNames.ASSERTION);
        }

        Map<String, Object> claims = jwtClaimsSet.getClaims();
        if (null == claims || claims.isEmpty()) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.ASSERTION);
        }

        String jwkSetUrl = (String) claims.get(JWK_SET_URL);
        if (!StringUtils.hasText(jwkSetUrl)) {
            jwkSetUrl = registeredClient.getClientSettings().getJwkSetUrl();
            if (!StringUtils.hasText(jwkSetUrl)) {
                throwError(OAuth2ErrorCodes.INVALID_REQUEST, JWK_SET_URL);
            }
        }

        URL url = null;
        try {
            url = new URL(jwkSetUrl);
        } catch (MalformedURLException e) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.ASSERTION);
        }

        // scope (OPTIONAL)
        Set<String> scopes = null;
        String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
        if (StringUtils.hasText(scope) &&
                parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.SCOPE);
        }
        if (StringUtils.hasText(scope)) {
            scopes = new HashSet<>(
                    Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
        }

        int length = assertion.lastIndexOf("\\.");
        Base64URL signedContent = Base64URL.from(assertion.substring(length + 1));


        JWKSet jwkSet = null;
        try {
            jwkSet = JWKSet.load(url);
        } catch (IOException e) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.ASSERTION);
        } catch (ParseException e) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.ASSERTION);
        }

        JWK jwk = jwkSet.getKeys().get(0);

        Signature signature;
        boolean result = false;
        try {
            signature = RSASSA.getSignerAndVerifier(jwsAlgorithm, new JCAContext().getProvider());
            signature.initVerify(jwk.toPublicJWK().toRSAKey().toRSAPublicKey());
            signature.update(signedContent.decode());
            result = signature.verify(signatureBase64.decode());
        } catch (JOSEException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        if (!result) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.ASSERTION);
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.ASSERTION) &&
                    !key.equals(OAuth2ParameterNames.SCOPE) &&
                    !key.equals(OAuth2ParameterNames.GRANT_TYPE)) {
                additionalParameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0]));
            }
        });

        return new JwtBearerAuthenticationToken(registeredClient, assertion, scopes, ClientAuthenticationMethod.PRIVATE_KEY_JWT,
                additionalParameters);
    }

    private MultiValueMap<String, String> getFormParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameterMap.forEach((key, values) -> {
            String queryString = StringUtils.hasText(request.getQueryString()) ? request.getQueryString() : "";
            // If not query parameter then it's a form parameter
            if (!queryString.contains(key) && values.length > 0) {
                for (String value : values) {
                    parameters.add(key, value);
                }
            }
        });
        return parameters;
    }

    private static void throwError(String errorCode, String parameterName) {
        throwError(errorCode, parameterName, DEFAULT_ERROR_URI);
    }

    private static void throwError(String errorCode, String parameterName, String errorUri) {
        OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
    }
}