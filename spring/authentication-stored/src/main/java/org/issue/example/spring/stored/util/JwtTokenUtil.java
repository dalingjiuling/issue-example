package org.issue.example.spring.stored.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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
     * @return 获取默认算法key
     */
    public static RSAKey getKey() {
        return key;
    }
}