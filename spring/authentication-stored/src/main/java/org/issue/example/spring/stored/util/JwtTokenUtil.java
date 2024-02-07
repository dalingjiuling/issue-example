package org.issue.example.spring.stored.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

/**
 * @Author: Mr.zhao
 * @Description: 自定义JSON-WEB-TOKEN工具，参照Spring Security
 * @Date:Create：in 2024/2/7 9:19
 * @Modified By：
 */
public class JwtTokenUtil {


    private static RSAKey key;

    static {
        initializeKey();
    }

    private static void initializeKey() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        key = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    static JWSHeader defaultHeaders() {
        return new JWSHeader(JWSAlgorithm.RS256);
    }

    static JWTClaimsSet accessTokenClaims(String subject) {
        Date date = new Date();
        return new JWTClaimsSet.Builder().subject(subject).issueTime(date).notBeforeTime(date).build();
    }

    /**
     * 针对userDetails生成token(私钥签名)
     *
     * @param userDetails 用户信息
     * @return 返回JWT token
     */
    public static String generateToken(UserDetails userDetails) throws JOSEException {
        String subject = userDetails.getUsername();
        SignedJWT signedJwt = new SignedJWT(defaultHeaders(), accessTokenClaims(subject));
        Assert.notNull(key, "未设置JSON Web密钥（JWK）！");
        JWSSigner jwsSigner = new RSASSASigner(key);
        signedJwt.sign(jwsSigner);
        return signedJwt.serialize();
    }

    /**
     * 验证token(公钥验证)
     *
     * @param token       jwt
     * @param userDetails 用户信息
     * @return 验证userDetails#userName是否和token中的sub属性一致
     */
    public static boolean validateToken(String token, UserDetails userDetails) throws Exception {
        if (verify(token)) {
            JWT jwt = JWTParser.parse(token);
            String sub = (String) jwt.getJWTClaimsSet().getClaim("sub");
            String userName = userDetails.getUsername();
            return userName.equals(sub);
        }
        return false;
    }

    /**
     * 验证token(公钥验证)
     *
     * @param token    jwt
     * @param userName 用户名
     * @return 验证userName是否和token中的sub属性一致
     */
    public static boolean validateToken(String token, String userName) throws Exception {
        if (verify(token)) {
            JWT jwt = JWTParser.parse(token);
            String sub = (String) jwt.getJWTClaimsSet().getClaim("sub");
            return userName.equals(sub);
        }
        return false;
    }

    /**
     * 获取token中sub属性值
     *
     * @param token jwt
     * @return 获取token中sub属性值
     */
    public static String getSubByToken(String token) throws Exception {
        JWT jwt = JWTParser.parse(token);
        return (String) jwt.getJWTClaimsSet().getClaim("sub");
    }

    /**
     * @return 获取默认算法key
     */
    public static RSAKey getKey() {
        return key;
    }

    /**
     * 设置指定算法key
     */
    public static void setRSAKey(RSAKey rsaKey) {
        key = rsaKey;
    }

    /**
     * 验证签名
     */
    private static boolean verify(String token) throws JOSEException, ParseException {
        Assert.notNull(key, "未设置JSON Web密钥（JWK）！");
        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) key.toPublicKey());
        Base64URL[] parts = JOSEObject.split(token);
        SignedJWT signedJWT = new SignedJWT(parts[0], parts[1], parts[2]);
        return signedJWT.verify(verifier);
    }
}