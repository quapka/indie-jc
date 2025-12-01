package test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.lang.IllegalStateException;
import java.lang.IllegalArgumentException;

import java.nio.charset.StandardCharsets;

import applet.HashCustom;
import applet.Constants;

public class HashCustomTest {

    private MessageDigest hasher;
    private static boolean initialized = false;

    public HashCustomTest() throws NoSuchAlgorithmException {
        hasher = MessageDigest.getInstance("SHA-256");
    }

    public void init(String tag) {
        byte[] tagHash = hasher.digest(tag.getBytes(StandardCharsets.UTF_8));
        hasher.reset();
        this.init(tagHash);
    }

    public void init(byte[] tagHash) {

        if ( tagHash.length != Constants.HASH_LEN ) {
            throw new IllegalArgumentException();
        }

        if ( !initialized && tagHash != null ) {
            hasher.update(tagHash, (short) 0x00, Constants.HASH_LEN);
            hasher.update(tagHash, (short) 0x00, Constants.HASH_LEN);
            initialized = true;
        } else {
            throw new IllegalStateException();
        }
    }

    public void update(byte[] inBuffer) {
        this.update(inBuffer, (short) 0, (short) inBuffer.length);
    }

    public void update(byte[] inBuffer, short offset, short length) {

        if ( !initialized ) {
            throw new IllegalStateException();
        }

        hasher.update(inBuffer, offset, length);
    }

    public byte[] digest() {
        return this.digest(null, (short) 0, (short) 0);
    }

    public byte[] digest(byte[] inBuffer) {
        return this.digest(inBuffer, (short) 0, (short) inBuffer.length);
    }

    public byte[] digest(byte[] inBuffer, short offset, short length) {

        if ( !initialized ) {
            throw new IllegalStateException();
        }
        if ( inBuffer != null ) {
            this.update(inBuffer, offset, length);
        }
        byte[] digest = hasher.digest();
        initialized = false;
        hasher.reset();

        return digest;
    }
}
