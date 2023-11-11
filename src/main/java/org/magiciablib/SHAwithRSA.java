package org.magiciablib;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * 使用SHAx算法对数据进行哈希,然后使用RSA算法对哈希值进行数字签名.
 *
 * <p>用于确保消息的完整性和验证消息发送者的身份.
 *
 * @author Shilin <br > magicianlib@gmail.com
 * @since 2023/11/11 10:53
 */
public enum SHAwithRSA {

    SHA1withRSA("SHA1withRSA"),
    SHA256withRSA("SHA256withRSA"),
    SHA384withRSA("SHA384withRSA"),
    SHA512withRSA("SHA512withRSA"),

    ;

    private final String algorithm;

    SHAwithRSA(String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * 签名
     */
    public String signatureHex(String rsaPriBase64, String plaintext) throws NoSuchAlgorithmException,
            InvalidKeySpecException, InvalidKeyException, SignatureException {
        return Hex.toHexString(signature(rsaPriBase64, plaintext));
    }

    public String signatureBase64(String rsaPriBase64, String plaintext) throws NoSuchAlgorithmException,
            InvalidKeySpecException, InvalidKeyException, SignatureException {
        return Base64.encodeToString(signature(rsaPriBase64, plaintext));
    }

    public byte[] signature(String rsaPriBase64, String plaintext) throws NoSuchAlgorithmException,
            InvalidKeySpecException, InvalidKeyException, SignatureException {
        return signature(Base64.decodeToByte(rsaPriBase64), plaintext);
    }

    public byte[] signature(byte[] rsaPri, String plaintext) throws NoSuchAlgorithmException,
            InvalidKeySpecException, InvalidKeyException, SignatureException {

        // 私钥证书
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(rsaPri);
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(keySpec);

        // 进行签名
        Signature spi = Signature.getInstance(algorithm);
        spi.initSign(privateKey);
        spi.update(plaintext.getBytes(StandardCharsets.UTF_8));

        return spi.sign();
    }

    /**
     * 验签
     */
    public boolean verifyHex(String rsaPubBase64, String plaintext, String signatureHex) throws NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        return verify(rsaPubBase64, plaintext, Hex.toByteArray(signatureHex));
    }

    public boolean verifyBase64(String rsaPubBase64, String plaintext, String signatureBase64) throws NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        return verify(rsaPubBase64, plaintext, Base64.decodeToByte(signatureBase64));
    }

    public boolean verify(String rsaPubBase64, String plaintext, byte[] signature) throws NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        return verify(Base64.decodeToByte(rsaPubBase64), plaintext, signature);
    }

    public boolean verify(byte[] rsaPub, String plaintext, byte[] signature) throws NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {

        // 公钥证书
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(rsaPub);
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);

        Signature spi = Signature.getInstance(algorithm);
        spi.initVerify(publicKey);
        spi.update(plaintext.getBytes(StandardCharsets.UTF_8));

        // 验签
        return spi.verify(signature);
    }

    /**
     * RSA key-pair
     */
    public static Map<String, String> genKeyPair(int keySize) throws Exception {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(keySize);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        Map<String, String> keyMap = new HashMap<>(2);
        keyMap.put("private", Base64.encodeToString(privateKey.getEncoded()));
        keyMap.put("public", Base64.encodeToString(publicKey.getEncoded()));

        return keyMap;
    }


    /**
     * Convert each byte to a hexadecimal string
     */
    public static String toHexString(byte[] data) {
        StringBuilder builder = new StringBuilder(2 * data.length);

        for (byte b : data) {
            builder.append(String.format("%02X", b));
        }

        return builder.toString();
    }

    public static void main(String[] args) throws Exception {

        Map<String, String> keyPair = genKeyPair(2048);

        String plaintext = "hello,world";

        String signature = SHAwithRSA.SHA1withRSA.signatureHex(keyPair.get("private"), plaintext);
        System.out.println(signature);

        boolean verify = SHAwithRSA.SHA1withRSA.verifyHex(keyPair.get("public"), plaintext, signature);
        System.out.println(verify);

    }
}