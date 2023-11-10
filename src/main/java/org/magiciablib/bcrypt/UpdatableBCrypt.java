package org.magiciablib.bcrypt;

import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.function.Consumer;

/**
 * <a href="https://bcrypt.online/">Bcrypt Hash Generator & Verifier</a>
 */
final class UpdatableBCrypt {

    private static final Logger LOGGER = LoggerFactory.getLogger(UpdatableBCrypt.class);

    /**
     * Also known as the Cost Factor.
     * <p>
     * see: <a href="https://security.stackexchange.com/questions/17207/recommended-of-rounds-for-bcrypt/17238#17238">How to Choose the Right Cost Factor for Bcrypt</a>
     */
    private final int LOG2_ROUNDS;

    private static final int DEFAULT_LOG2_ROUNDS = 10;

    public UpdatableBCrypt() {
        this(DEFAULT_LOG2_ROUNDS);
    }

    public UpdatableBCrypt(int log2Rounds) {
        this.LOG2_ROUNDS = log2Rounds;
    }

    public String hash(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt(LOG2_ROUNDS));
    }

    public boolean verifyHash(String password, String hash) {
        return BCrypt.checkpw(password, hash);
    }

    public boolean verifyAndUpdateHash(String password, String hash, Consumer<String> updateFunc) {
        if (BCrypt.checkpw(password, hash)) {
            int rounds = getRounds(hash);
            // It might be smart to only allow increasing the rounds.
            // If someone makes a mistake the ability to undo it would be nice though.
            if (rounds != LOG2_ROUNDS) {
                LOGGER.debug("Updating password from {} rounds to {}", rounds, LOG2_ROUNDS);
                updateFunc.accept(hash(password));
                return true;
            }
            return true;
        }
        return false;
    }

    /*
     * Copied and pasted from BCrypt internals :(. Ideally a method
     * to exports parts would be public. We only care about rounds
     * currently.
     */
    private int getRounds(String salt) {
        char minor;
        int offset;

        if (salt.charAt(0) != '$' || salt.charAt(1) != '2') {
            throw new IllegalArgumentException("Invalid salt version");
        }
        if (salt.charAt(2) == '$') {
            offset = 3;
        } else {
            minor = salt.charAt(2);
            if (minor != 'a' || salt.charAt(3) != '$') {
                throw new IllegalArgumentException("Invalid salt revision");
            }
            offset = 4;
        }

        // Extract number of rounds
        if (salt.charAt(offset + 2) > '$') {
            throw new IllegalArgumentException("Missing salt rounds");
        }

        // log2 rounds
        return Integer.parseInt(salt.substring(offset, offset + 2));
    }
}