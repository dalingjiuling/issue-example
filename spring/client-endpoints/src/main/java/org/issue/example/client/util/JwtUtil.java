package org.issue.example.client.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSVerifierFactory;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.core.io.ClassPathResource;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.text.ParseException;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.UUID;

public class JwtUtil {

    private static JWSVerifierFactory jwsVerifierFactory = new DefaultJWSVerifierFactory();

    /**
     * 加载自定义的密钥对
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

    /**
     * 使用RSA（是一种非对称算法） 算法加签生成JWT（JSON WEB TOKEN）
     */
    public static String rsaSign(JWTClaimsSet claimsSet) throws JOSEException {
        KeyPair keyPair = loadRsaKey();
        RSASSASigner signer = new RSASSASigner(keyPair.getPrivate());

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
        signedJWT.sign(signer);
        String token = signedJWT.serialize();
        return token;
    }

    /**
     * 使用HMAC算法加签生成JWT（JSON WEB TOKEN）
     *
     * @param clientSecret 密钥，长度必须至少为33位
     * @param claimsSet    加签数据
     * @return JWT
     * @throws JOSEException
     */
    public static String hmacSign(String clientSecret, JWTClaimsSet claimsSet) throws JOSEException {
        JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;


        OctetSequenceKey key = new OctetSequenceKey.Builder(clientSecret.getBytes(StandardCharsets.UTF_8))
                .keyID(UUID.randomUUID().toString())
                .build();

        // 参考：DefaultJWSSignerFactory
        JWSSigner signer = new MACSigner(key);
        // Apply JCA context
        JCAContext jcaContext = new JCAContext();
        signer.getJCAContext().setSecureRandom(jcaContext.getSecureRandom());
        signer.getJCAContext().setProvider(jcaContext.getProvider());

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(jwsAlgorithm), claimsSet);
        signedJWT.sign(signer);
        String token = signedJWT.serialize();
        return token;
    }

    /**
     * 根据jwks地址获取publicKey
     * 参考{@link com.nimbusds.jose.jwk.source.RemoteJWKSet#get(JWKSelector, SecurityContext)}
     *
     * @param jwksUrl 根据publicKey地址
     * @return JWK集合
     */
    public static JWKSet loadJWKSByUrl(String jwksUrl) throws IOException, ParseException {

        URL jwkSetURL = new URL(jwksUrl);

        ResourceRetriever jwkSetRetriever = new DefaultResourceRetriever(
                RemoteJWKSet.resolveDefaultHTTPConnectTimeout(),
                RemoteJWKSet.resolveDefaultHTTPReadTimeout(),
                RemoteJWKSet.resolveDefaultHTTPSizeLimit());

        Resource res = jwkSetRetriever.retrieveResource(jwkSetURL);

        JWKSet jwkSet = JWKSet.parse(res.getContent());
        return jwkSet;
    }

    /**
     * 根据公钥验证JWT（JSON WEB TOKEN）<br/>
     * 参考{@link com.nimbusds.jwt.proc.DefaultJWTProcessor#process(SignedJWT, SecurityContext)}
     *
     * @param jwksUrl 根据jwks地址获取publicKey地址
     * @param jwt     要验证的JWT（JSON WEB TOKEN）
     * @return 验证结果，true正确
     */
    public static boolean verifyJWT(String jwksUrl, String jwt) throws ParseException, IOException, JOSEException {

        Base64URL[] parts = JOSEObject.split(jwt);
        SignedJWT signedJWT = new SignedJWT(parts[0], parts[1], parts[2]);

        JWSHeader jwsHeader = JWSHeader.parse(parts[0].decodeToString());

        JWKMatcher jwkMatcher = JWKMatcher.forJWSHeader(jwsHeader);

        JWKSelector jwkSelector = new JWKSelector(jwkMatcher);
        List<JWK> jwkMatches = jwkSelector.select(loadJWKSByUrl(jwksUrl));

        // 获取公钥
        List<Key> sanitizedKeyList = new LinkedList<>();
        for (Key key : KeyConverter.toJavaKeys(jwkMatches)) {
            if (key instanceof PublicKey || key instanceof SecretKey) {
                sanitizedKeyList.add(key);
            }
        }

        ListIterator<? extends Key> it = sanitizedKeyList.listIterator();

        while (it.hasNext()) {

            JWSVerifier verifier = jwsVerifierFactory.createJWSVerifier(jwsHeader, it.next());

            if (verifier == null) {
                continue;
            }

            final boolean validSignature = signedJWT.verify(verifier);

            return validSignature;
        }
        return false;
    }
}