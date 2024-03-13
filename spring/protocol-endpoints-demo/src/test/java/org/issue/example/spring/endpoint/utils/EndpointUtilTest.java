package org.issue.example.spring.endpoint.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.nio.charset.StandardCharsets;

import static org.issue.example.spring.endpoint.utils.EndpointUtil.getJWKUrl;

public class EndpointUtilTest {

    final String code = "uAitnWW4vTX_CpGlDDKyrHiUpvyAVasamD8DYwdmI2LVc21JeOaMneJKAjWdfT9XcwwEuW43lJwcq_R_XJ-jcieQzVEYfa4iXOZy6T06T4FatG21Vlrb2YGjHBDQZIKV";
    final String token = "eyJraWQiOiI0MjkyOTY4OC1kMDkxLTQ5Y2MtYjkxNC0xYzgwNmMyZDU3NWMiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoib2lkYy1jbGllbnQiLCJuYmYiOjE3MDk3OTMzOTIsInNjb3BlIjpbImNsaWVudC5jcmVhdGUiXSwiaXNzIjoiaHR0cDovLzEyNy4wLjAuMTo2MDA0IiwiZXhwIjoxNzA5ODA3NzkyLCJpYXQiOjE3MDk3OTMzOTIsImp0aSI6IjJmNDI4OTBkLWUzNGMtNGZmNC04ZjkzLTdjOGIwZDE4YTVmMyJ9.Yc-kMcRzpoBIYRQmc1UPBrvu5rAmHc_MZa5kxLAScQFbkvIxHTSBUldZr-NLgmY6Z2O9zuVarwWmRXZhqhKvjPx8GcIfB9iC5o5HMH1KPcv2irq2O_QzEtLh_BgnnHFWqYLoqHB-1PXUsLZzy_PtBUDkRZBSzBXaZo9Vt5-TfL8TTkn--po6490qXtngd16uiO3nfZrbX6NHf8DTI4_8nZ7nbh1mE3jwPe_ESZeB0NuaHvp3ARpYMK96Iqu0lRcyNe84xvtlpco05ZSFgJq4Ca17Gbxhsw9FL8RShF1MiyPo4XrkExmIKJIEW1HdJ_2ig3uJ6ePmdV03KbsbLoJXLw";
    final String jwk ="eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvaWRjLWNsaWVudCIsImF1ZCI6WyJodHRwOi8vMTI3LjAuMC4xOjYwMDQiLCJodHRwOi8vMTI3LjAuMC4xOjYwMDQvb2F1dGgyL3Rva2VuIiwiaHR0cDovLzEyNy4wLjAuMTo2MDA0L29hdXRoMi9pbnRyb3NwZWN0IiwiaHR0cDovLzEyNy4wLjAuMTo2MDA0L29hdXRoMi9yZXZva2UiXSwiandrLXNldC11cmwiOiJodHRwOi8vMTI3LjAuMC4xOjgwODkvY2xpZW50L2p3a3MiLCJzY29wZSI6WyJjbGllbnQuY3JlYXRlIl0sImlzcyI6Im9pZGMtY2xpZW50IiwiZXhwIjoxNzEwNDAwNzY3LCJpYXQiOjE3MTAzMTQzNjd9.7aQXAmtoANdBgllyLwoCwsphZ7_qERkO-7jNOFfGM4ii5QBcV7IwD2WzAzQLMcbLisN0RY-nNp95NxYwPmTynk6_ypXGA2aHNiRlBM1ekPWQLID7po6jjZSuUvoh7pQupGLOr_crzCX93YWTVmqjtknCItUSR83l97-63xiBs0La_7bSM8cdwzLbdapIKhWDE9-KcZ2L-MptuTOjca3iaY0gSOFK-qHnOSOJ6xwGXI5q-Ga4bbYejXOIxs8ct1nhqyScs-7EavEHZq7ni5EuiyTvTai1rr_u6bP6UkTxvq6VhCJM1dS8L7gl0wWLFYWpKCqrJ5bPkNFcTx83x0HCIQ";

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
    public void usingJWTsForClientAuthenticationTest() {
        System.out.println(EndpointUtil.usingJWTsForClientAuthentication(code, "oidc-client", jwk));
    }

    @Test
    public void usingJWTsAsAuthorizationGrantsTest(){
        System.out.println(EndpointUtil.usingJWTsAsAuthorizationGrants(jwk));
    }

    @Test
    public void getJWKUrlTEST() {
        System.out.println(getJWKUrl());
    }
}