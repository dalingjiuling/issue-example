package org.issue.example.spring.grants.util;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * 端点工具类
 */
public class EndpointUtil {

    public static String usingJWTsAsAuthorizationGrants(String jwt) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("fetch(\"http://127.0.0.1:6004/oauth2/token\", {");
        stringBuilder.append("\"headers\": {");
        stringBuilder.append("\"content-type\": \"application/x-www-form-urlencoded; charset=UTF-8\",");
        stringBuilder.append("},");
        stringBuilder.append("\"method\": \"POST\",");
        stringBuilder.append("\"body\":\"");
        stringBuilder.append("grant_type=");
        stringBuilder.append(URLEncoder.encode("urn:ietf:params:oauth:grant-type:jwt-bearer", StandardCharsets.UTF_8));
        stringBuilder.append("&");
        stringBuilder.append("assertion=");
        stringBuilder.append(URLEncoder.encode(jwt, StandardCharsets.UTF_8));

        stringBuilder.append("\"");
        stringBuilder.append("}).then(json=>console.log(json));");
        return stringBuilder.toString();
    }
}
