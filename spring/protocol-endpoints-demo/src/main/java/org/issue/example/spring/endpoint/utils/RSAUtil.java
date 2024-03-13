package org.issue.example.spring.endpoint.utils;

import com.alibaba.fastjson2.JSONObject;
import com.nimbusds.jose.util.Base64URL;
import org.springframework.lang.NonNull;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Map;

/**
 * RSA非对称加密方式,公钥加密私钥解密,私钥签名公钥认证
 */
public class RSAUtil {

    // 最大的加密明文长度
    private static final int MAX_ENCRYPT_BLOCK = 245;
    private static final String modulus = "26168556431921736210705394603775065264677880808098660256853084963681922776886840975671491750535314226410558576544220498382753372111914896332734229824095731063867192401744076336238464696337028549093059749398292594467178402641559401764769141098918254955771754412048274639342942309986444859550396593316877893383769342622764018668902067278320724640021198727750128197059779202988844587843592186916470338726704068000464086618522724316047166668638677445101060344830269474398548511296490233478756582521724895648712318787318581191288499850782739188188093451937678093641651811994152232945721170957509016754619899953699334281931";
    private static final String privateExponent = "65537";
    // 最大的解密密文长度
    public static final int MAX_DECRYPT_BLOCK = 256;

    /**
     * RSA非对称加密
     *
     * @param publicKeyJSON 加密key JSON数据
     * @param data          加密数据
     * @return 加密后数据
     */
    public static String RSAPublicKeyEncrypted(@NonNull String publicKeyJSON, @NonNull String data) {

        Map<String, String> map = JSONObject.parseObject(publicKeyJSON, Map.class);
        // String kty = map.get("kty");
        // String kid = map.get("kid");
        String e = map.get("e");
        String n = map.get("n");

        BigInteger publicExponent = new BigInteger(1, Base64URL.from(e).decode());
        BigInteger modulus = new BigInteger(1, Base64URL.from(n).decode());
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);


        KeyFactory factory = null;
        try {
            factory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }

        RSAPublicKey rsaPublicKey = null;
        try {
            rsaPublicKey = (RSAPublicKey) factory.generatePublic(rsaPublicKeySpec);
        } catch (InvalidKeySpecException ex) {
            ex.printStackTrace();
        }

        Cipher encryptCipher;
        String encryptedString = null;
        try {
            encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
            //分段加密
            int inputLen = data.getBytes().length;
            byte[] inputBytes = data.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedBytes;
            if (MAX_ENCRYPT_BLOCK >= inputLen) {
                encryptedBytes = encryptCipher.doFinal(inputBytes);
            } else {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                int offSet = 0;
                byte[] cache;
                int i = 0;
                //对数据分段加密
                int count = 0;

                while ((count = (inputLen - offSet)) > 0) {

                    if (count >= MAX_ENCRYPT_BLOCK) {
                        // 加密出来的长度是256
                        cache = encryptCipher.doFinal(inputBytes, offSet, MAX_ENCRYPT_BLOCK);
                    } else {
                        cache = encryptCipher.doFinal(inputBytes, offSet, count);
                    }
                    out.write(cache, 0, cache.length);
                    out.flush();
                    i++;
                    offSet = i * MAX_ENCRYPT_BLOCK;
                }
                encryptedBytes = out.toByteArray();
                out.close();
            }
            return Base64URL.encode(encryptedBytes).toString();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        } catch (NoSuchPaddingException ex) {
            ex.printStackTrace();
        } catch (IllegalBlockSizeException ex) {
            ex.printStackTrace();
        } catch (BadPaddingException ex) {
            ex.printStackTrace();
        } catch (InvalidKeyException ex) {
            ex.printStackTrace();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return encryptedString;
    }

    /**
     * RAS解密
     *
     * @param privateKey 私钥
     * @param data       解密数据
     * @return 解密后的数据
     */
    public static String RSAPrivateKeyDecrypted(@NonNull PrivateKey privateKey, @NonNull byte[] data) {
        // 使用私钥解密数据
        Cipher decryptCipher = null;
        try {
            decryptCipher = Cipher.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        try {
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        int inputLen = data.length;
        byte[] decryptedBytes;

        try {
            if (MAX_DECRYPT_BLOCK >= inputLen) {
                decryptedBytes = decryptCipher.doFinal(data);
            } else {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                int offSet = 0;
                byte[] cache;
                int i = 0;
                //对数据分段加密
                int count = 0;

                while ((count = (inputLen - offSet)) > 0) {

                    if (count >= MAX_DECRYPT_BLOCK) {
                        cache = decryptCipher.doFinal(data, offSet, MAX_DECRYPT_BLOCK);
                    } else {
                        cache = decryptCipher.doFinal(data, offSet, count);
                    }
                    out.write(cache, 0, cache.length);
                    out.flush();
                    i++;
                    offSet = i * MAX_DECRYPT_BLOCK;
                }
                decryptedBytes = out.toByteArray();
                out.close();
            }
            return new String(decryptedBytes);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static RSAPrivateKey getPrivateKey() {
        RSAPrivateKeySpec privateSpec = new RSAPrivateKeySpec(new BigInteger(modulus), new BigInteger(privateExponent));
        KeyFactory factory = null;
        try {
            factory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }

        RSAPrivateKey rsaPrivateKey = null;
        try {
            rsaPrivateKey = (RSAPrivateKey) factory.generatePrivate(privateSpec);
        } catch (InvalidKeySpecException ex) {
            ex.printStackTrace();
        }
        return rsaPrivateKey;
    }
}