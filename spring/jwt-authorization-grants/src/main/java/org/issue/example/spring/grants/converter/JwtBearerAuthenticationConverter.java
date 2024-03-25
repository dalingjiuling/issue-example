package org.issue.example.spring.grants.converter;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.*;

/**
 * 自定义”urn:ietf:params:oauth:grant-type:jwt-bearer“转换器
 * <a href="https://datatracker.ietf.org/doc/html/rfc7523#section-2.2">参考<a/>
 */
public class JwtBearerAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
        MultiValueMap<String, String> parameters = getFormParameters(request);

        if (parameters.getFirst(OAuth2ParameterNames.GRANT_TYPE) == null ||
                parameters.getFirst(OAuth2ParameterNames.ASSERTION) == null) {
            return null;
        }

        // grant_type (REQUIRED)
        String grantType = parameters.getFirst(OAuth2ParameterNames.GRANT_TYPE);
        if (parameters.get(OAuth2ParameterNames.GRANT_TYPE).size() != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        if (!AuthorizationGrantType.JWT_BEARER.getValue().equals(grantType)) {
            return null;
        }

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        // assertion (REQUIRED)
        String assertion = parameters.getFirst(OAuth2ParameterNames.ASSERTION);
        if (parameters.get(OAuth2ParameterNames.ASSERTION).size() != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        Map<String, Object> additionalParameters = getParametersIfMatchesAuthorizationCodeGrantRequest(parameters,
                OAuth2ParameterNames.GRANT_TYPE,
                OAuth2ParameterNames.ASSERTION);

        return new JwtBearerAuthenticationToken(clientPrincipal,
                assertion, additionalParameters);
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

    static Map<String, Object> getParametersIfMatchesAuthorizationCodeGrantRequest(MultiValueMap<String, String> multiValueParameters,
                                                                                   String... exclusions) {
        for (String exclusion : exclusions) {
            multiValueParameters.remove(exclusion);
        }

        Map<String, Object> parameters = new HashMap<>();
        multiValueParameters.forEach((key, value) ->
                parameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0])));

        return parameters;
    }
}