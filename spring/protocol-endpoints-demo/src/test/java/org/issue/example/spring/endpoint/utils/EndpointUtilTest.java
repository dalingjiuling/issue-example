package org.issue.example.spring.endpoint.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.nio.charset.StandardCharsets;

import static org.issue.example.spring.endpoint.utils.EndpointUtil.getJWKUrl;

public class EndpointUtilTest {

    final String code = "E0zETTWH7ONBwmSEzmJT-R53ecCL-2cRTkR5oNGP5edVUsU2-uZGqEDRNHv7wDOFJRqM5Gh8Kk9awxOo7rYcXebbXUr0411x1SednZ4B5pEExOoMhpdNUOfcm3hFa05y";
    final String token = "eyJraWQiOiI0MjkyOTY4OC1kMDkxLTQ5Y2MtYjkxNC0xYzgwNmMyZDU3NWMiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoib2lkYy1jbGllbnQiLCJuYmYiOjE3MDk3OTMzOTIsInNjb3BlIjpbImNsaWVudC5jcmVhdGUiXSwiaXNzIjoiaHR0cDovLzEyNy4wLjAuMTo2MDA0IiwiZXhwIjoxNzA5ODA3NzkyLCJpYXQiOjE3MDk3OTMzOTIsImp0aSI6IjJmNDI4OTBkLWUzNGMtNGZmNC04ZjkzLTdjOGIwZDE4YTVmMyJ9.Yc-kMcRzpoBIYRQmc1UPBrvu5rAmHc_MZa5kxLAScQFbkvIxHTSBUldZr-NLgmY6Z2O9zuVarwWmRXZhqhKvjPx8GcIfB9iC5o5HMH1KPcv2irq2O_QzEtLh_BgnnHFWqYLoqHB-1PXUsLZzy_PtBUDkRZBSzBXaZo9Vt5-TfL8TTkn--po6490qXtngd16uiO3nfZrbX6NHf8DTI4_8nZ7nbh1mE3jwPe_ESZeB0NuaHvp3ARpYMK96Iqu0lRcyNe84xvtlpco05ZSFgJq4Ca17Gbxhsw9FL8RShF1MiyPo4XrkExmIKJIEW1HdJ_2ig3uJ6ePmdV03KbsbLoJXLw";
    final String jwk = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvaWRjLWNsaWVudCIsImF1ZCI6WyJodHRwOi8vMTI3LjAuMC4xOjYwMDQiLCJodHRwOi8vMTI3LjAuMC4xOjYwMDQvb2F1dGgyL3Rva2VuIiwiaHR0cDovLzEyNy4wLjAuMTo2MDA0L29hdXRoMi9pbnRyb3NwZWN0IiwiaHR0cDovLzEyNy4wLjAuMTo2MDA0L29hdXRoMi9yZXZva2UiXSwiandrLXNldC11cmwiOiJodHRwOi8vMTI3LjAuMC4xOjgwODkvY2xpZW50L2p3a3MiLCJzY29wZSI6WyJjbGllbnQuY3JlYXRlIl0sImlzcyI6Im9pZGMtY2xpZW50IiwiZXhwIjoxNzEwNDc0MDYzLCJpYXQiOjE3MTAzODc2NjN9.Epx4rjjHfs-pwLWYfdukXAm_C-TQaCT9mBlMDN6RLuJJFDsBsluSXNda5-g8i01-rEhsKfvqf4y7aqgIl_YHRoRmYVgZDepvpsoqJ1AOgKgOZOQGNTpQGxV4eQZk-x3ZOGjhHqNdSp3cxjERE4aFcfp0SYYEen-_hEU6MN6AUJS1CauLPnJADTSlRer0A4qfeqMcAvEqF73AhUgcnHjVLqNjBdVhIkzc365dUXlVID51sZP4jfKSorz-LEr1Sv9iIw5ooKiSgRYCDP0-3e0hF97UOrUojO2FI_ObH4q2FpjaE5GjI3j6Gt-C6MyHoY9L0Rm-DAuYGzhG4jtaF9tP2A";
    final String HS256_JWT ="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvaWRjLWNsaWVudC10d28iLCJhdWQiOlsiaHR0cDovLzEyNy4wLjAuMTo2MDA0IiwiaHR0cDovLzEyNy4wLjAuMTo2MDA0L29hdXRoMi90b2tlbiIsImh0dHA6Ly8xMjcuMC4wLjE6NjAwNC9vYXV0aDIvaW50cm9zcGVjdCIsImh0dHA6Ly8xMjcuMC4wLjE6NjAwNC9vYXV0aDIvcmV2b2tlIl0sImp3ay1zZXQtdXJsIjoiaHR0cDovLzEyNy4wLjAuMTo4MDg5L2NsaWVudC9qd2tzIiwic2NvcGUiOlsiY2xpZW50LmNyZWF0ZSJdLCJpc3MiOiJvaWRjLWNsaWVudC10d28iLCJleHAiOjE3MTA1NzA3OTgsImlhdCI6MTcxMDQ4NDM5OH0.zO_N0s5UgbsuYxOEwcJwW_btTdd0qBdzzt4NO9Q47w0";

    @Test
    public void base64D() {
        System.out.println(new String(Base64.decodeBase64(token), StandardCharsets.ISO_8859_1));
    }

    /**
     * 获取授权码链接<br/>
     * http://127.0.0.1:6004/oauth2/authorize?response_type=code&client_id=oidc-client&scope=client.create&redirect_uri=http%3A%2F%2F127.0.0.1%3A8089%2Fclient%2Foauth2%2Fcode
     * http://127.0.0.1:6004/oauth2/authorize?response_type=code&client_id=oidc-client-two&scope=client.create&redirect_uri=http%3A%2F%2F127.0.0.1%3A8089%2Fclient%2Foauth2%2Fcode
     */
    @Test
    public void getAuthorizationCodeUrlEncodedTest() {
        System.out.println(EndpointUtil.getAuthorizationCodeUrlEncoded("oidc-client"));
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
    public void getJWKUrlTEST() {
        System.out.println(getJWKUrl());
    }

    @Test
    public void getOpenidUserInfoUrlTest() {
        System.out.println(EndpointUtil.getOpenidUserInfoUrl(token));
    }

    @Test
    public void getClientRegistrationUrlTest() throws JsonProcessingException {
        System.out.println(EndpointUtil.getClientRegistrationUrl(token));
    }

    /**
     * clientAuthenticationMethod:  client_secret_basic
     */
    @Test
    public void getAccessTokenByClientSecretBasic() {
        System.out.println(EndpointUtil.getAccessTokenUrl("oidc-client", code, "secret",
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
    }

    /**
     * clientAuthenticationMethod:  client_secret_post
     */
    @Test
    public void getAccessTokenByClientSecretPost() {
        System.out.println(EndpointUtil.getAccessTokenUrl("oidc-client", code, "secret",
                ClientAuthenticationMethod.CLIENT_SECRET_POST));
    }

    /**
     * clientAuthenticationMethod:  private_key_jwt
     */
    @Test
    public void getAccessTokenByPrivateKeyJwt() {
        System.out.println(EndpointUtil.getAccessTokenUrl("oidc-client", code, jwk,
                ClientAuthenticationMethod.PRIVATE_KEY_JWT));
    }

    /**
     * clientAuthenticationMethod: client_secret_jwt
     */
    @Test
    public void getAccessTokenByClientSecretJwt() {
        System.out.println(EndpointUtil.getAccessTokenUrl("oidc-client-two", code, HS256_JWT,
                ClientAuthenticationMethod.CLIENT_SECRET_JWT));
    }

    @Test
    public void authorizationGrantTypeTest() {
        System.out.println(EndpointUtil.authorizationGrantType("oidc-client", "secret",
                AuthorizationGrantType.CLIENT_CREDENTIALS));
    }

}