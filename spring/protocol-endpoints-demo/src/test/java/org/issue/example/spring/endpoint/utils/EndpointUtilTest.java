package org.issue.example.spring.endpoint.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.nio.charset.StandardCharsets;

import static org.issue.example.spring.endpoint.utils.EndpointUtil.getJWKUrl;

public class EndpointUtilTest {

    final String code = "5ZO0W8KkZQqpxlSojBhIp0x775lMWVZeeYq1BUqRdl1aX-Z8EbvLRkbyLtH9PJuzxrCWn9L7bpLfkBxFjx72oUUtC2jPdQ8hKl8lq3nXmiIntncyzqHLyIEeI87Kl6VD";
    final String token = "eyJraWQiOiI0MjkyOTY4OC1kMDkxLTQ5Y2MtYjkxNC0xYzgwNmMyZDU3NWMiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoib2lkYy1jbGllbnQiLCJuYmYiOjE3MDk3OTMzOTIsInNjb3BlIjpbImNsaWVudC5jcmVhdGUiXSwiaXNzIjoiaHR0cDovLzEyNy4wLjAuMTo2MDA0IiwiZXhwIjoxNzA5ODA3NzkyLCJpYXQiOjE3MDk3OTMzOTIsImp0aSI6IjJmNDI4OTBkLWUzNGMtNGZmNC04ZjkzLTdjOGIwZDE4YTVmMyJ9.Yc-kMcRzpoBIYRQmc1UPBrvu5rAmHc_MZa5kxLAScQFbkvIxHTSBUldZr-NLgmY6Z2O9zuVarwWmRXZhqhKvjPx8GcIfB9iC5o5HMH1KPcv2irq2O_QzEtLh_BgnnHFWqYLoqHB-1PXUsLZzy_PtBUDkRZBSzBXaZo9Vt5-TfL8TTkn--po6490qXtngd16uiO3nfZrbX6NHf8DTI4_8nZ7nbh1mE3jwPe_ESZeB0NuaHvp3ARpYMK96Iqu0lRcyNe84xvtlpco05ZSFgJq4Ca17Gbxhsw9FL8RShF1MiyPo4XrkExmIKJIEW1HdJ_2ig3uJ6ePmdV03KbsbLoJXLw";
    final String jwks="{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"3339c010-d699-4d5d-b818-aabf123cc2e4\",\"n\":\"w6ln-c5nNReeRRxvFs9Wk02itp4_ucBQJ45eeRANMAQ74Odq4guUu87ROQRF2JbvlLaFbW-1Q26BrdAzNrclaPHQA7fsX-7V4tFmK-WVpryiLZNW4fnGvUF05tr2WrdpZMnhtkFBJUFY04dXVsYfmEu7Qg-Dx5GU2UsKEmyZrQSmaxRab4v-9LNWtY6zGMrLNZOEFu-UuxDokzRzDMR6sXFB8hKFukTFdEhz8_rqoRkJ-Ha4H8RIqzcpxjOu7qXwCyOXGBpFshU9e1hKlOtiljk33MSqostQkU-KCI6icQKZkON1TJxh9saEIR4nRa0Hkjzazaay70-tGA4eukgDqQ\"}";


    @Test
    public void base64D() {
        System.out.println(new String(Base64.decodeBase64(token), StandardCharsets.ISO_8859_1));
    }

    @Test
    public void getAuthorizationCodeUrlEncodedTest() {
        System.out.println(EndpointUtil.getAuthorizationCodeUrlEncoded());
    }

    @Test
    public void getAccessTokenUrlTest() {
        System.out.println(EndpointUtil.getAccessTokenUrl("oidc-client", code));
    }

    @Test
    public void getIntrospectionUrlTest() {
        System.out.println(EndpointUtil.getIntrospectionUrl(token));
    }

    @Test
    public void getRevocationUrlTest() {
        System.out.println(EndpointUtil.getRevocationUrl(token));
    }

    @Test
    public void getOpenidUserInfoUrlTest() {
        System.out.println(EndpointUtil.getOpenidUserInfoUrl(token));
    }

    @Test
    public void getClientRegistrationUrlTest() throws JsonProcessingException {
        System.out.println(EndpointUtil.getClientRegistrationUrl(token));
    }

    @Test
    public void getAccessTokenUrlByMethod() {
        System.out.println(EndpointUtil.getAccessTokenUrl("oidc-client", code, "secret",
                ClientAuthenticationMethod.PRIVATE_KEY_JWT));
    }

    @Test
    public void usingJWTsForClientAuthenticationTest(){
        System.out.println(EndpointUtil.usingJWTsForClientAuthentication(code, "oidc-client",token));
    }

    @Test
    public void usingJWTsAsAuthorizationGrantsTest(){
        System.out.println(EndpointUtil.usingJWTsAsAuthorizationGrants(jwks));
    }

    @Test
    public void getJWTTest(){
        System.out.println(EndpointUtil.getJWT(jwks));
    }

    @Test
    public void getJWKUrlTEST() {
        System.out.println(EndpointUtil.getJWT(getJWKUrl()));
    }
}