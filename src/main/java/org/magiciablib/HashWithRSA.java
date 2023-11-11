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
 * <p>该类提供常见的 HashWithRSA 组合算法, 用于提供数据签名和验签.</p>
 *
 * <p>HashWithRSA 指的是使用 RSA 加密算法结合哈希函数进行数字签名或数据加密。
 * RSA(Rivest–Shamir–Adleman)是一种非对称加密算法,而哈希函数则用于生成消息
 * 摘要(即签名).</p>
 *
 * <p>加密和签名的区别:
 * 加密和签名都是为了安全性考虑,但有所不同.加密是为了防止信息被泄露,签名是为了防止信息被篡改.</p>
 *
 * <p>加密过程</p>
 * <ul>
 * <li>1.A生成一对密钥(公钥和私钥).私钥不公开,A自己保留.公钥为公开的,任何人可以获取.</li>
 * <li>2.A传递自己的公钥给B,B使用A的<em>公钥对消息进行加密</em>.</li>
 * <li>3.A接收到B加密的消息,利用A自己的<em>私钥对消息进行解密</em></li>
 * </ul>
 * <p>整个过程中,只用A的私钥才能对消息进行解密,防止消息被泄露.</p>
 *
 * <p>签名过程
 * <ul>
 * <li>1.A生成一对密钥(公钥和私钥).私钥不公开,A自己保留.公钥为公开的,任何人可以获取.</li>
 * <li>2.A用自己的私钥对消息进行加签,形成签名,并将签名和消息本身一起传递给B.</li>
 * <li>3.B收到消息后,通过A的公钥进行验签.如果验签成功,则证明消息是A发送的.</li>
 * </ul>
 * <p>
 * 整个过程,只有使用A私钥签名的消息才能被验签成功.即使知道了消息内容,也无法伪造签名,防止消息被篡改.
 *
 * @author Shilin <br > magicianlib@gmail.com
 * @since 2023/11/11 10:53
 */
public enum HashWithRSA {

    MD5withRSA,
    SHA1withRSA,
    SHA256withRSA,
    SHA384withRSA,
    SHA512withRSA,

    ;

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
        Signature spi = Signature.getInstance(this.name());
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

        Signature spi = Signature.getInstance(this.name());
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

        String signature = HashWithRSA.SHA1withRSA.signatureHex(keyPair.get("private"), plaintext);
        System.out.println(signature);

        boolean verify = HashWithRSA.SHA1withRSA.verifyHex(keyPair.get("public"), plaintext, signature);
        System.out.println(verify);

    }
}