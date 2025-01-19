package org.magiciablib.aes;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * 全局使用一个 AES Cipher
 */
public final class AESEncryptionUnique {

    private AESEncryptionUnique() {
    }

    private static final Cipher ENCRYPT_CIPHER;
    private static final Cipher DECRYPT_CIPHER;

    /**
     * 128位(16字节)初始化向量
     */
    private static final String IV_128 = "NFe,2'e9l'w51/GO";
    /**
     * 128位(16字节)密钥
     */
    private static final String KEY_128 = "W`p7Q!Cv3#56b(fD";

    static {
        try {
            IvParameterSpec iv = new IvParameterSpec(IV_128.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec spec = new SecretKeySpec(KEY_128.getBytes(StandardCharsets.UTF_8), "AES");

            ENCRYPT_CIPHER = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            ENCRYPT_CIPHER.init(Cipher.ENCRYPT_MODE, spec, iv);

            DECRYPT_CIPHER = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            DECRYPT_CIPHER.init(Cipher.DECRYPT_MODE, spec, iv);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 加密
     *
     * @param plainText 要加密的文本
     */
    public static String encrypt(String plainText) throws Exception {
        byte[] encrypted = ENCRYPT_CIPHER.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * 解密
     *
     * @param encryptedText 要解密的密文
     */
    public static String decrypt(String encryptedText) throws Exception {
        byte[] original = DECRYPT_CIPHER.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(original);
    }

    public static void main(String[] args) throws Exception {
        String plainText = "Hello, World!";

        String encryptedText = encrypt(plainText);
        System.out.println("Encrypted Text: " + encryptedText);

        String decryptedText = decrypt(encryptedText);
        System.out.println("Decrypted Text: " + decryptedText);
    }
}