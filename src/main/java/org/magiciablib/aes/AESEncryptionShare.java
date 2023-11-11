package org.magiciablib.aes;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class AESEncryptionShare {

    private AESEncryptionShare() {
    }

    /**
     * 加密
     *
     * @param key        128位(16字节)密钥
     * @param initVector 128位(16字节)始化向量
     * @param plaintext  要加密的文本
     */
    public static String encrypt(String key, String initVector, String plaintext) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * 解密
     *
     * @param key           128位(16字节)密钥
     * @param initVector    128位(16字节)始化向量
     * @param encryptedText 要解密的密文
     */
    public static String decrypt(String key, String initVector, String encryptedText) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encryptedText));

        return new String(original);
    }

    public static void main(String[] args) throws Exception {
        String key = "E[~W1N8tF5i@ep.8";        // 128位(16字节)密钥
        String initVector = "2U[K'gLl3y%Y#9v3"; // 128位(16字节)初始化向量
        String plainText = "Hello, World!";

        String encryptedText = encrypt(key, initVector, plainText);
        System.out.println("Encrypted Text: " + encryptedText);

        String decryptedText = decrypt(key, initVector, encryptedText);
        System.out.println("Decrypted Text: " + decryptedText);
    }
}