package org.issue.example.client.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class JwtUtilTest {

    @Test
    public void getJWT() throws JOSEException {
        String clientId = "oidc-client";
        String clientSecret = "secret";

        List<String> aud = new ArrayList<>();
        aud.add("http://127.0.0.1:6004");
        aud.add("http://127.0.0.1:6004/oauth2/token");
        aud.add("http://127.0.0.1:6004/oauth2/introspect");
        aud.add("http://127.0.0.1:6004/oauth2/revoke");

        // 前四个属性是必须的（iss、sub、aud、exp），参考JwtClientAssertionDecoderFactory#defaultJwtValidatorFactory
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                // 发行者：固定clientId
                .issuer(clientId)
                // 主体：固定clientId
                .subject(clientId)
                // 授权服务器的相关地址
                .audience(aud)
                // 过期时间 24h
                .expirationTime(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24))
                // 访问时间
                .issueTime(new Date())
                // 范围
                .claim("scope", new String[]{"client.create"})
                .claim("jwk-set-url", "http://127.0.0.1:8089/client/jwks")
                .build();

        String jwt = JwtUtil.rsaSign(claimsSet);
        System.out.println(jwt);
        // eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvaWRjLWNsaWVudCIsImF1ZCI6WyJodHRwOi8vMTI3LjAuMC4xOjYwMDQiLCJodHRwOi8vMTI3LjAuMC4xOjYwMDQvb2F1dGgyL3Rva2VuIiwiaHR0cDovLzEyNy4wLjAuMTo2MDA0L29hdXRoMi9pbnRyb3NwZWN0IiwiaHR0cDovLzEyNy4wLjAuMTo2MDA0L29hdXRoMi9yZXZva2UiXSwiandrLXNldC11cmwiOiJodHRwOi8vMTI3LjAuMC4xOjgwODkvY2xpZW50L2p3a3MiLCJzY29wZSI6WyJjbGllbnQuY3JlYXRlIl0sImlzcyI6Im9pZGMtY2xpZW50IiwiZXhwIjoxNzEwNDAwNzY3LCJpYXQiOjE3MTAzMTQzNjd9.7aQXAmtoANdBgllyLwoCwsphZ7_qERkO-7jNOFfGM4ii5QBcV7IwD2WzAzQLMcbLisN0RY-nNp95NxYwPmTynk6_ypXGA2aHNiRlBM1ekPWQLID7po6jjZSuUvoh7pQupGLOr_crzCX93YWTVmqjtknCItUSR83l97-63xiBs0La_7bSM8cdwzLbdapIKhWDE9-KcZ2L-MptuTOjca3iaY0gSOFK-qHnOSOJ6xwGXI5q-Ga4bbYejXOIxs8ct1nhqyScs-7EavEHZq7ni5EuiyTvTai1rr_u6bP6UkTxvq6VhCJM1dS8L7gl0wWLFYWpKCqrJ5bPkNFcTx83x0HCIQ
    }
}