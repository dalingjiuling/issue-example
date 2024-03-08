package org.issue.example.spring.endpoint.converter;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.impl.RSASSA;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.SignedJWT;
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
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.util.*;

/**
 * @Author: Mr.Zhao
 * @Description:
 * @Date:Create：in 2024/3/7 15:50
 * @Modified By:
 */
public class JwtBearerAuthenticationConverter implements AuthenticationConverter {
    private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7523#section-2.1";
    private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken(
            "anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    private final RegisteredClientRepository registeredClientRepository;
    private HttpSecurity httpSecurity;
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private JWKSource<SecurityContext> jwkSource;

    public JwtBearerAuthenticationConverter(HttpSecurity httpSecurity) {
        this.httpSecurity = httpSecurity;
        this.jwkSource = httpSecurity.getSharedObject(JWKSource.class);
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

        String[] parts = assertion.split("\\.");
        if (3 != parts.length) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.ASSERTION);
        }

        Base64 headerBase64 = new Base64(parts[0]);
        Base64 payloadBase64 = new Base64(parts[1]);
        Base64 signatureBase = new Base64(parts[2]);

        String headerJson = headerBase64.decodeToString();
        String payload = payloadBase64.decodeToString();

        Map<String, Object> claims = null;
        Map<String, Object> header = null;
        try {
            claims = JSONObjectUtils.parse(payload);
            header = JSONObjectUtils.parse(headerJson);
        } catch (ParseException e) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.ASSERTION);
        }

        String clientId = (String) claims.get("sub");
        /*
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.ASSERTION);
        }

        JwsAlgorithm jwsAlgorithm = registeredClient.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm();
        JwsHeader jwsHeader = JwsHeader.with(jwsAlgorithm).build();

        List<String> audience = new ArrayList<>();
        audience.add(registeredClient.getClientId());

        Instant issuedAt = Instant.now();
        // 构造参考：JwtClientAssertionDecoderFactory#defaultJwtValidatorFactory方法
        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .issuer(registeredClient.getClientId())
                .subject(registeredClient.getClientId())
                .audience(audience)
                .issuedAt(issuedAt)// 访问时间
                .expiresAt(issuedAt.plus(registeredClient.getTokenSettings().getAccessTokenTimeToLive()))// 过期时间
                .issuer(registeredClient.getClientSettings().getJwkSetUrl())
                .claim(OAuth2ParameterNames.SCOPE, registeredClient.getScopes())
                .build();


        JwtEncoderParameters jwtEncoderParameters = JwtEncoderParameters.from(jwsHeader, jwtClaimsSet);

        NimbusJwtEncoder nimbusJwtEncoder =  new NimbusJwtEncoder(jwkSource);
        Jwt jwtAssertion = nimbusJwtEncoder.encode(jwtEncoderParameters);
        */
        ImmutableJWKSet immutableJWKSet = (ImmutableJWKSet)jwkSource;
        JWKSet jwkSet = immutableJWKSet.getJWKSet();
        JWK jwk= jwkSet.getKeys().get(0);

        Base64URL privateExponentBase64 =((RSAKey) jwk).getPrivateExponent();
        Base64URL modulusBase64 =((RSAKey) jwk).getModulus();

        // e、n的其实是publicExponent和modulus的base64格式
        // 正常私钥签名，公钥验证。现在是客户端用公钥签名，服务端用私钥验证
        BigInteger publicExponent = new BigInteger(1, privateExponentBase64.decode());
        BigInteger modulus = new BigInteger(1, modulusBase64.decode());

        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);

        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        PublicKey publicKey = null;
        try {
            publicKey = keyFactory.generatePublic(rsaPublicKeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }


        Signature verifier = null;
        try {
            verifier = Signature.getInstance("SHA256withRSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        try {
            verifier.initVerify(publicKey);

        } catch (InvalidKeyException e) {

        }

        boolean result;

        try {
            verifier.update((headerBase64+"."+headerBase64).getBytes(StandardCharsets.UTF_8));
            result = verifier.verify(signatureBase.decode());
        } catch (SignatureException e) {

        }

        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.ASSERTION) &&
                    !key.equals(OAuth2ParameterNames.SCOPE) &&
                    !key.equals(OAuth2ParameterNames.GRANT_TYPE)) {
                additionalParameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0]));
            }
        });

        return new JwtBearerAuthenticationToken(null, assertion, scopes, ClientAuthenticationMethod.PRIVATE_KEY_JWT,
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