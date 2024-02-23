package org.issue.example.spring.endpoint.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.Test;

public class EndpointUtilTest {

    final String code = "maohpLk2v5D-T-UrjzO-AkBtJpQqJwhxagVElAKaY-lz7J9FqYLACVMfZ8mlZNOt6ngEArurxuzRCHKW73xTitw2PYFPUVUsSHss4CEO4NQGLyv9wWu_uqAB0FeD81gI";
    final String token = "eyJraWQiOiJiNTk5MGMyOS1lOTY1LTQwMmEtYTQxYy05MTE3NzQxNDExYmEiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoib2lkYy1jbGllbnQiLCJuYmYiOjE3MDg2NzUyODUsInNjb3BlIjpbImNsaWVudC5jcmVhdGUiXSwiaXNzIjoiaHR0cDovLzEyNy4wLjAuMTo2MDA0IiwiZXhwIjoxNzA4Njg5Njg1LCJpYXQiOjE3MDg2NzUyODUsImp0aSI6IjU4ODVkNDc5LWQ1ZGUtNGRlOS1hNTcwLWJhNTIzZjUzMDhlNiJ9.OOJzON_WyhR_D0-LE9nU08faclKQ6ISGrBImxIHtXKV1cEd3kShumZVrxS8WtkUlqFSK5MUv9USepjlT09eDw2mkTZBHxHNnPPSinCNIBohOXXBcuaM5LGhK2uXT27aa2MFzOpx8rkGyLij4b3Na5KnysENlcaTd0fM0zZh9qM8gqDPEWqW5qSWKHceC9jCfzqxXAqfFL2fRg3opA897uhSXb9G6BXIv2CA3hOHMi0VAAXmnf4Uyr_vlE-wKhXo-7PkUoTzRG-HQTjTMshSU6TspmH3LT1oiPl2E0JC5fc40hVuOvpguPtZQZKMTHRxXaFoz6jZryfBTQsU1jBaQqQ";

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
}