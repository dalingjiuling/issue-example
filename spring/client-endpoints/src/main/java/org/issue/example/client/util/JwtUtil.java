package org.issue.example.client.util;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.issue.example.client.endpoint.JwksController;

import java.security.KeyPair;

public class JwtUtil {

    /**
     * 使用RSA算法加签生成jwt
     */
    public static String rsaSign(JWTClaimsSet claimsSet) throws JOSEException {
        KeyPair keyPair = JwksController.loadRsaKey();
        RSASSASigner signer = new RSASSASigner(keyPair.getPrivate());

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
        signedJWT.sign(signer);
        String token = signedJWT.serialize();
        return token;
    }
}
