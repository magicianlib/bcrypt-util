package org.magiciablib;

public final class Base64 {
    public static String encodeToString(byte[] encoded) {
        return java.util.Base64.getEncoder().encodeToString(encoded);
    }

    public static byte[] decodeToByte(String decoded) {
        return java.util.Base64.getDecoder().decode(decoded);
    }
}