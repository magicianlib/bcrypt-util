package org.magiciablib.bcrypt;

import java.util.UUID;
import java.util.function.Consumer;

public final class BCryptUtil {

    private static final UpdatableBCrypt BCRYPT = new UpdatableBCrypt(12);

    public static String hash(String password) {
        return BCRYPT.hash(password);
    }

    public static boolean verifyHash(String password, String hash) {
        return BCRYPT.verifyHash(password, hash);
    }

    public static boolean verifyAndUpdateHash(String password, String hash, Consumer<String> updateFunc) {
        return BCRYPT.verifyAndUpdateHash(password, hash, updateFunc);
    }

    public static void main(String[] args) {

        for (int i = 0; i < 20; i++) {
            String password = UUID.randomUUID().toString();
            long start = System.currentTimeMillis();
            String hash = hash(password);
            System.out.println(System.currentTimeMillis() - start);
            System.out.println(hash);
            System.out.println("verifyHash: " + verifyHash(password, hash));
        }
    }
}