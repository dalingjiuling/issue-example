package org.issue.example.client.endpoint;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.core.io.ClassPathResource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * 获取客户端JWTS
 */
@RestController
public class JwksController {

    @GetMapping("client/jwks")
    public String jwkSet() {
        KeyPair keyPair = loadRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return jwkSet.toString();
    }

    /**
     * 加载自定义的 密钥对
     */
    public static KeyPair loadRsaKey() {
        KeyPair keyPair;
        try {
            ClassPathResource resource = new ClassPathResource("my.jks");
            KeyStore ks = KeyStore.getInstance("jks");
            ks.load(resource.getInputStream(), "123456".toCharArray());
            PrivateKey priKey = (PrivateKey) ks.getKey("my-key", "123456".toCharArray());
            PublicKey pubKey = ks.getCertificate("my-key").getPublicKey();
            keyPair = new KeyPair(pubKey, priKey);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return keyPair;
    }
}