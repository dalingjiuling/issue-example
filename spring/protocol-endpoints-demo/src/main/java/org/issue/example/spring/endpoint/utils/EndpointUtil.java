package org.issue.example.spring.endpoint.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.apache.commons.codec.binary.Base64;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static java.time.temporal.ChronoUnit.DAYS;

/**
 * @Author: Mr.Zhao
 * @Description: 端点工具类
 * @Date:Create：in 2024/2/19 15:55
 * @Modified By:
 */
public class EndpointUtil {

    private static final String redirect_uri = "http://127.0.0.1:8089/client/oauth2/code";

    /**
     * 请求端点：/oauth2/authorize <br/>
     * <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1">参考</a><br/>
     * 请求方式 get/post，请求context-type:application/x-www-form-urlencoded <br/>
     */
    public static String getAuthorizationCodeUrlEncoded(String client_id) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("http://127.0.0.1:6004/oauth2/authorize?");
        stringBuilder.append("response_type=code&");
        stringBuilder.append("client_id=");
        stringBuilder.append(URLEncoder.encode(client_id, StandardCharsets.UTF_8));
        stringBuilder.append("&");
        stringBuilder.append("scope=");
        // stringBuilder.append(URLEncoder.encode("openid profile client.create", StandardCharsets.UTF_8));
        // 调用/connect/register时，scope只能是client.create
        stringBuilder.append(URLEncoder.encode("client.create", StandardCharsets.UTF_8));
        stringBuilder.append("&");
        stringBuilder.append("redirect_uri=");
        stringBuilder.append(URLEncoder.encode(redirect_uri, StandardCharsets.UTF_8));
        return stringBuilder.toString();
    }

    /**
     * 请求端点：/oauth2/token <br/>
     * 请求方式 post，请求context-type:application/x-www-form-urlencoded <br/>
     * <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3">参考</a><br/>
     * google浏览器f12，打开console，输入如下：<br/>
     * fetch("http://127.0.0.1:6004/oauth2/token", { <br/>
     * "headers": { <br/>
     * "content-type": "application/x-www-form-urlencoded; charset=UTF-8", <br/>
     * "Authorization": "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW" <br/>
     * }, <br/>
     * "method": "POST", <br/>
     * "body": "grant_type=authorization_code&code=b6-oXiVzgmckTQmbHHFGc0TjvzfDUUGRGzUXYRbkl8iuFFH_v-7UxuCxNzMRLaTC1A0Epgj5fOJebIuj2nLlw_RFG95JZMtOSCuV6M7ztWGlvAr_tsBiRSTsGfnOzGIv&redirect_uri=http%3A%2F%2F127.0.0.1%3A6004%2Flogin%2Foauth2%2Fcode%2Foidc-client"<br/>
     * }).then(res=>res.json()).then(json=>console.log(json)); <br/>
     *
     * @param client_id                       客户端ID
     * @param code                            授权码，只能用一次
     * @param clientSecret_or_clientAssertion 客户端秘钥或者clientAssertion（jwt）
     * @param method                          客户端身份验证方法
     * @return Fetch API 调用逻辑
     */
    public static String getAccessTokenUrl(String client_id, String code, String clientSecret_or_clientAssertion,
                                           ClientAuthenticationMethod method) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("fetch(\"http://127.0.0.1:6004/oauth2/token\", {");
        stringBuilder.append("\"headers\": {");
        stringBuilder.append("\"content-type\": \"application/x-www-form-urlencoded; charset=UTF-8\",");
        if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(method)) {
            stringBuilder.append("\"Authorization\": \"Basic " +
                    Base64.encodeBase64URLSafeString((client_id + ":" + clientSecret_or_clientAssertion).getBytes(StandardCharsets.UTF_8)) + "\"");
        }
        stringBuilder.append("},");
        stringBuilder.append("\"method\": \"POST\",");
        stringBuilder.append("\"body\":\"");
        stringBuilder.append("grant_type=authorization_code&");
        stringBuilder.append("code=");
        stringBuilder.append(URLEncoder.encode(code, StandardCharsets.UTF_8));
        stringBuilder.append("&");

        if (ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(method)) {

            stringBuilder.append("client_id=");
            stringBuilder.append(URLEncoder.encode(client_id, StandardCharsets.UTF_8));
            stringBuilder.append("&");

            stringBuilder.append("client_secret=");
            stringBuilder.append(URLEncoder.encode(clientSecret_or_clientAssertion, StandardCharsets.UTF_8));
            stringBuilder.append("&");

            stringBuilder.append("redirect_uri=");
            stringBuilder.append(URLEncoder.encode(redirect_uri, StandardCharsets.UTF_8));

        } else if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(method)) {

            stringBuilder.append("client_id=");
            stringBuilder.append(URLEncoder.encode(client_id, StandardCharsets.UTF_8));
            stringBuilder.append("&");
            stringBuilder.append("redirect_uri=");
            stringBuilder.append(URLEncoder.encode(redirect_uri, StandardCharsets.UTF_8));

        } else if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.equals(method) ||
                ClientAuthenticationMethod.CLIENT_SECRET_JWT.equals(method)) {

            stringBuilder.append("client_id=");
            stringBuilder.append(URLEncoder.encode(client_id, StandardCharsets.UTF_8));
            stringBuilder.append("&");

            stringBuilder.append("redirect_uri=");
            stringBuilder.append(URLEncoder.encode(redirect_uri, StandardCharsets.UTF_8));
            stringBuilder.append("&");

            stringBuilder.append("client_assertion_type=");
            stringBuilder.append(URLEncoder.encode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", StandardCharsets.UTF_8));
            stringBuilder.append("&");

            stringBuilder.append("client_assertion=");
            stringBuilder.append(URLEncoder.encode(clientSecret_or_clientAssertion, StandardCharsets.UTF_8));
        }
        stringBuilder.append("\"");
        stringBuilder.append("}).then(res=>res.json()).then(json=>console.log(json));");
        return stringBuilder.toString();
    }

    /**
     * 请求端点：/oauth2/introspect <br/>
     * 请求方式 post，请求context-type:application/x-www-form-urlencoded <br/>
     * <a href="https://datatracker.ietf.org/doc/html/rfc7662#section-2.1">参考</a><br/>
     * 返回一个围绕token的元信息，包括该token当前是否处于活动状态 <br/>
     *
     * @param token 访问token
     * @return
     */
    public static String getIntrospectionUrl(String token) {
        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append("fetch(\"http://127.0.0.1:6004/oauth2/introspect\", {");
        stringBuilder.append("\"headers\": {");
        stringBuilder.append("\"content-type\": \"application/x-www-form-urlencoded; charset=UTF-8\",");
        stringBuilder.append("\"Authorization\": \"Basic " + Base64.encodeBase64URLSafeString("oidc-client:secret".getBytes(StandardCharsets.UTF_8)) + "\"");
        stringBuilder.append("},");
        stringBuilder.append("\"method\": \"POST\",");
        stringBuilder.append("\"body\":\"");

        stringBuilder.append("token=");
        stringBuilder.append(URLEncoder.encode(token, StandardCharsets.UTF_8));

        stringBuilder.append("\"");
        stringBuilder.append("}).then(res=>res.json()).then(json=>console.log(json));");
        return stringBuilder.toString();
    }

    /**
     * 请求端点：/oauth2/revoke <br/>
     * 请求方式 post，请求context-type:application/x-www-form-urlencoded <br/>
     * <a href="https://datatracker.ietf.org/doc/html/rfc7009#section-2.1">参考</a><br/>
     * token_type_hint (令牌类型提示) 可选的，关于提交用于吊销的令牌类型的提示。客户端可以传递此参数，以帮助授权服务器优化令牌查找。<br/>
     * 如果服务器无法使用给定提示定位令牌，则必须将搜索扩展到所有支持的令牌类型。<br/>
     * 授权服务器可能会忽略此参数，特别是在能够自动检测令牌类型的情况下。 <br/>
     * 本规范定义了两个这样的值：access_token、refresh_token。<br/>
     * 注意：</br>
     * 无效令牌不会导致错误响应，因为客户端无法以合理的方式处理此类错误。此外，吊销请求的目的(使特定令牌无效)已经实现。</br>
     * 响应体的内容被客户端忽略，因为所有必要的信息都在响应代码中传递。</br>
     * 无效的令牌类型提示值将被授权服务器忽略，并且不会影响吊销响应。</br>
     *
     * @param token 访问token
     * @return 如果令牌已被成功撤销或者如果客户端提交了无效令牌，则授权服务器以HTTP状态代码200进行响应。
     */
    public static String getRevocationUrl(String token) {
        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append("fetch(\"http://127.0.0.1:6004/oauth2/revoke\", {");
        stringBuilder.append("\"headers\": {");
        stringBuilder.append("\"content-type\": \"application/x-www-form-urlencoded; charset=UTF-8\",");
        stringBuilder.append("\"Authorization\": \"Basic " + Base64.encodeBase64URLSafeString("oidc-client:secret".getBytes(StandardCharsets.UTF_8)) + "\"");
        stringBuilder.append("},");
        stringBuilder.append("\"method\": \"POST\",");
        stringBuilder.append("\"body\":\"");

        stringBuilder.append("token=");
        stringBuilder.append(URLEncoder.encode(token, StandardCharsets.UTF_8));

        stringBuilder.append("\"");
        stringBuilder.append("}).then(json=>console.log(json));");
        return stringBuilder.toString();
    }

    /**
     * 请求端点：/.well-known/oauth-authorization-server <br/>
     * 请求方式 GET <br/>
     * <a href="https://datatracker.ietf.org/doc/html/rfc8414#section-3.1">参考</a><br/>
     * 相应结果：</br>
     * {
     * "issuer": "http://127.0.0.1:6004",
     * "authorization_endpoint": "http://127.0.0.1:6004/oauth2/authorize",
     * "device_authorization_endpoint": "http://127.0.0.1:6004/oauth2/device_authorization",
     * "token_endpoint": "http://127.0.0.1:6004/oauth2/token",
     * "token_endpoint_auth_methods_supported": [
     * "client_secret_basic",
     * "client_secret_post",
     * "client_secret_jwt",
     * "private_key_jwt"
     * ],
     * "jwks_uri": "http://127.0.0.1:6004/oauth2/jwks",
     * "response_types_supported": [
     * "code"
     * ],
     * "grant_types_supported": [
     * "authorization_code",
     * "client_credentials",
     * "refresh_token",
     * "urn:ietf:params:oauth:grant-type:device_code"
     * ],
     * "revocation_endpoint": "http://127.0.0.1:6004/oauth2/revoke",
     * "revocation_endpoint_auth_methods_supported": [
     * "client_secret_basic",
     * "client_secret_post",
     * "client_secret_jwt",
     * "private_key_jwt"
     * ],
     * "introspection_endpoint": "http://127.0.0.1:6004/oauth2/introspect",
     * "introspection_endpoint_auth_methods_supported": [
     * "client_secret_basic",
     * "client_secret_post",
     * "client_secret_jwt",
     * "private_key_jwt"
     * ],
     * "code_challenge_methods_supported": [
     * "S256"
     * ]
     * }
     *
     * @return 地址
     */
    public static String getAuthorizationServerMetadataUrl() {
        return "http://127.0.0.1:6004/.well-known/oauth-authorization-server";
    }

    /**
     * 请求端点：/oauth2/jwks <br/>
     * 无论我们使用哪种签名算法，都存在密钥泄漏的风险。所以为了提高安全性，我们通常建议定期轮换或者更新密钥。但显然手动将新的密钥配置到服务器中并不是一个好的选择，特别是多个服务器在使用同一组密钥时。在多租户的场景下，我们可能还需要为不同的租户提供不同的密钥。
     *
     * 所以我们需要一种更加高效的管理和分发密钥的机制，而这就是 JWKS Endpoint 存在的目的。
     * 请求方式 GET <br/>
     * <a href="https://datatracker.ietf.org/doc/html/rfc7517">参考</a><br/>
     * 相应结果：</br>
     * {
     * "keys": [
     * {
     * "kty": "RSA",
     * "e": "AQAB",
     * "kid": "3ee60469-8a9f-431d-bda2-362aca249e4a",
     * "n": "vl4G7SN8MmzOkLiO1vC8E1sZ6_DjI08wT5OoxZpo3SRQZ_ePYRBtCMycc1Q9oMIFtHnkua7KY2iSgi2m1FPXur5Sng7KklcXYqllPJPeZcwBOlQz5PrW3OpH99LS6bvtwYFYPsajSem36MvBLnj9Jys89WHLBXxKBkcBmwTb3zh5ke8R7SirdVcwG_t6ealRi2adebkT-c8B5e7rhcr6z24NlViNdp6ifeL9_6m7cDMCc6KtoXpJs5hIYYaZops2holCi9ACyofwUNTUzhxyVJpqWbjrfqRKP2KNiCg9sc6J_fQDaWPEn5yhW50VhPoyWgveOjtVdtQLxzRHI0q8Ow"
     * }
     * ]
     * }
     *
     * @return 地址
     */
    public static String getJWKUrl() {
        return "http://127.0.0.1:6004/oauth2/jwks";
    }

    /**
     * 请求端点：.well-known/openid-configuration <br/>
     * 请求方式 GET <br/>
     *
     * @return 地址
     */
    public static String getOpenidConfigurationUrl() {
        return "http://127.0.0.1:6004/.well-known/openid-configuration";
    }

    /**
     * 请求端点：/userinfo <br/>
     * 请求方式 支持GET/POST <br/>
     * <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">参考</a><br/>
     *
     * @param token 令牌
     * @return
     */
    public static String getOpenidUserInfoUrl(String token) {
        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append("fetch(\"http://127.0.0.1:6004/userinfo\", {");
        stringBuilder.append("\"headers\": {");
        stringBuilder.append("\"Authorization\": \"Bearer " + token + "\"");
        stringBuilder.append("},");
        stringBuilder.append("\"method\": \"POST\"");
        stringBuilder.append("}).then(res=>res.json()).then(json=>console.log(json));");
        return stringBuilder.toString();
    }

    /**
     * 请求端点：/connect/register <br/>
     * 请求方式 支持POST 请求context-type:application/json <br/>
     *
     * @return
     */
    public static String getClientRegistrationUrl(String token) throws JsonProcessingException {
        OidcClientRegistration oidcClientRegistration = OidcClientRegistration
                .builder()
                .clientId("my-client")
                .clientName("ergo")
                .clientSecret("{noop}password")
                .clientIdIssuedAt(Instant.now())  // 创建客户端的时间
                .clientSecretExpiresAt(Instant.now().plus(30, DAYS)) // 客户端密码过期时间
                .tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue())
                .grantType("authorization_code")
                .grantType("refresh_token")
                .redirectUri("http://127.0.0.1:6004/login/oauth2/code/my-client")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("client.create")
                .build();

        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        String data = objectMapper.writeValueAsString(oidcClientRegistration.getClaims());

        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append("fetch(\"http://127.0.0.1:6004/connect/register\", {");
        stringBuilder.append("\"headers\": {");
        stringBuilder.append("\"content-type\": \"application/json; charset=UTF-8\",");
        stringBuilder.append("\"Authorization\": \"Bearer " + token + "\"");
        stringBuilder.append("},");
        stringBuilder.append("\"method\": \"POST\",");


        stringBuilder.append("\"body\":");
        stringBuilder.append("JSON.stringify(");
        stringBuilder.append(data);
        stringBuilder.append(")");

        stringBuilder.append("}).then(res=>res.json()).then(json=>console.log(json));");
        return stringBuilder.toString();
    }

    /**
     * 请求端点：/connect/logout <br/>
     * 请求方式 支持GET/POST <br/>
     * <a href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout">参考</a><br/>
     *
     * @param token
     * @return
     */
    public static String getOpenidLogoutUrl(String token) {
        return null;
    }
}