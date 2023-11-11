package org.magiciablib;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * <p>Hmac(Hash-based Message Authentication Code)是一种使用哈希函数
 * 和秘密密钥来生成消息认证码的算法.</p>
 *
 * <p>HMAC通过将密钥混入哈希运算中,提供了一种更强大的消息认证方法,防范了一
 * 些针对普通哈希的攻击.</p>
 *
 * @author Shilin <br > magicianlib@gmail.com
 * @since 2023/11/11 10:52
 */
public enum Hmac {
    HmacMD5,
    HmacSHA1,
    HmacSHA256,
    HmacSHA384,
    HmacSHA512,
    ;

    public String hmacHex(String secret, String plaintext) throws NoSuchAlgorithmException, InvalidKeyException {
        return Hex.toHexString(hmac(secret, plaintext));
    }

    public String hmacBase64(String secret, String plaintext) throws NoSuchAlgorithmException, InvalidKeyException {
        return Base64.encodeToString(hmac(secret, plaintext));
    }

    public byte[] hmac(String secret, String plaintext) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(this.name());
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(), this.name());
        mac.init(keySpec);
        return mac.doFinal(plaintext.getBytes());
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {

        String secret = "f$s1f@9.";
        String plaintext = "hello,world";

        System.out.println(HmacSHA1.hmacHex(secret, plaintext));
        System.out.println(HmacSHA1.hmacBase64(secret, plaintext));
    }
}