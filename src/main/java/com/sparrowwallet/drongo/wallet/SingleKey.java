package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.crypto.*;

import java.math.BigInteger;
import java.util.Arrays;

/** Private material for one non-derived key. The public key is stored separately in its keystore. */
public class SingleKey extends Persistable implements EncryptableItem {
    private final byte[] privateKey;
    private final boolean compressed;
    private final EncryptedData encryptedKey;

    public SingleKey(byte[] privateKey, boolean compressed) {
        checkPrivateKey(privateKey);
        this.privateKey = privateKey.clone();
        this.compressed = compressed;
        this.encryptedKey = null;
    }

    private static void checkPrivateKey(byte[] privateKey) {
        if(privateKey == null || privateKey.length != 32) {
            throw new IllegalArgumentException("Private key must contain 32 bytes");
        }
        BigInteger scalar = new BigInteger(1, privateKey);
        if(scalar.signum() == 0 || scalar.compareTo(ECKey.CURVE.getN()) >= 0) {
            throw new IllegalArgumentException("Private key is outside the valid secp256k1 range");
        }
    }

    public SingleKey(ECKey key) {
        this(key.getPrivKeyBytes(), key.isCompressed());
    }

    public SingleKey(EncryptedData encryptedKey, boolean compressed) {
        checkEncryptedKey(encryptedKey);
        this.privateKey = null;
        this.compressed = compressed;
        this.encryptedKey = encryptedKey.copy();
    }

    private static void checkEncryptedKey(EncryptedData encryptedKey) {
        if(encryptedKey == null || !new EncryptionType(EncryptionType.Deriver.ARGON2, EncryptionType.Crypter.AES_CBC_PKCS7).equals(encryptedKey.getEncryptionType()) ||
                encryptedKey.getInitialisationVector() == null || encryptedKey.getInitialisationVector().length != AESKeyCrypter.BLOCK_LENGTH ||
                encryptedKey.getEncryptedBytes() == null || encryptedKey.getEncryptedBytes().length != 48 ||
                encryptedKey.getKeySalt() == null || encryptedKey.getKeySalt().length != Argon2KeyDeriver.SPRW1_PARAMETERS.saltLength) {
            throw new IllegalArgumentException("Invalid encrypted private key");
        }
    }

    public ECKey getKey() {
        if(isEncrypted()) {
            throw new IllegalStateException("Private key is encrypted");
        }
        checkPrivateKey(privateKey);
        return ECKey.fromPrivate(privateKey, compressed);
    }

    public boolean isCompressed() {
        return compressed;
    }

    @Override
    public boolean isEncrypted() {
        if((privateKey == null) == (encryptedKey == null)) {
            throw new IllegalStateException("Private key must have exactly one private representation");
        }
        if(encryptedKey != null) {
            checkEncryptedKey(encryptedKey);
        }
        return encryptedKey != null;
    }

    @Override
    public byte[] getSecretBytes() {
        if(isEncrypted()) {
            throw new IllegalStateException("Private key is encrypted");
        }
        return privateKey.clone();
    }

    @Override
    public EncryptedData getEncryptedData() {
        return encryptedKey == null ? null : encryptedKey.copy();
    }

    @Override
    public EncryptionType getEncryptionType() {
        return new EncryptionType(EncryptionType.Deriver.ARGON2, EncryptionType.Crypter.AES_CBC_PKCS7);
    }

    @Override
    public long getCreationTimeMillis() {
        return 0;
    }

    public SingleKey encrypt(Key key) {
        if(isEncrypted()) {
            throw new IllegalStateException("Private key is already encrypted");
        }
        byte[] secret = getSecretBytes();
        try {
            SingleKey result = new SingleKey(getEncryptionType().getCrypter().getKeyCrypter().encrypt(secret, null, key), compressed);
            result.setId(getId());
            return result;
        } finally {
            Arrays.fill(secret, (byte)0);
        }
    }

    public SingleKey decrypt(CharSequence password) {
        if(!isEncrypted()) {
            throw new IllegalStateException("Private key is not encrypted");
        }
        Key key = getEncryptionType().getDeriver().getKeyDeriver(encryptedKey.getKeySalt()).deriveKey(password);
        try {
            return decrypt(key);
        } finally {
            key.clear();
        }
    }

    public SingleKey decrypt(Key key) {
        if(!isEncrypted()) {
            throw new IllegalStateException("Private key is not encrypted");
        }
        byte[] secret = getEncryptionType().getCrypter().getKeyCrypter().decrypt(encryptedKey, key);
        try {
            SingleKey result = new SingleKey(secret, compressed);
            result.setId(getId());
            return result;
        } finally {
            Arrays.fill(secret, (byte)0);
        }
    }

    public SingleKey copy() {
        SingleKey result = isEncrypted() ? new SingleKey(encryptedKey.copy(), compressed) : new SingleKey(privateKey, compressed);
        result.setId(getId());
        return result;
    }

    public void clear() {
        if(privateKey != null) {
            Arrays.fill(privateKey, (byte)0);
        }
    }
}
