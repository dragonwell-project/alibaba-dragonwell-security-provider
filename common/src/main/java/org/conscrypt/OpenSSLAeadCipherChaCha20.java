package org.conscrypt;

import java.security.InvalidKeyException;
import java.util.Locale;

public class OpenSSLAeadCipherChaCha20 extends OpenSSLAeadCipher {

    public OpenSSLAeadCipherChaCha20() {
        super(Mode.POLY1305);
    }

    @Override
    String getCipherName(int keyLength, Mode mode) {
        return "chacha20-" + mode.toString().toLowerCase(Locale.US);
    }

    @Override
    String getBaseCipherName() {
        return "ChaCha20";
    }

    @Override
    void checkSupportedKeySize(int keySize) throws InvalidKeyException {
        if (keySize != 32) {
            throw new InvalidKeyException("Unsupported key size: " + keySize
                    + " bytes (must be 32)");
        }
    }

    @Override
    int getCipherBlockSize() {
        return 0;
    }

    @Override
    boolean allowsNonceReuse() {
        return true;
    }

}
