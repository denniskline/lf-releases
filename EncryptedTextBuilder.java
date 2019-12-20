package com.jpmc.gti.cassandra.reaper.util;
/*
File: EncryptedTextBuilder

Copyright 2019 JPMorgan Chase
All Rights Reserved
*/

import org.apache.commons.lang3.StringUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class EncryptedTextBuilder {

    // ************************************************************************
    // Constants

    private static final String PREFIX = "{cipher}";
    private static final String REGEX_PREFIX = "\\{cipher\\}";
    private static final String DEFAULT_SALT = "deadbeef";
    private static final String DEFAULT_CIPHER = "AES/CBC/PKCS5Padding";
    private static final int DEFAULT_ITERATION_COUNT = 1024;
    private static final int DEFAULT_KEY_STRENGTH = 256;

    // ************************************************************************
    // Member Variables

    private String salt = DEFAULT_SALT;
    private String cipher = DEFAULT_CIPHER;
    private Integer iterationCount = DEFAULT_ITERATION_COUNT;
    private Integer keyStrength = DEFAULT_KEY_STRENGTH;
    private String systemPropertySecret;

    // ************************************************************************
    // Constructor

    private EncryptedTextBuilder() {
    }

    // ************************************************************************
    // Implementation

    public static EncryptedTextBuilder create() {
        return new EncryptedTextBuilder();
    }

    public String decrypt(String encryptedText) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {

        String trimmedText = StringUtils.trimToNull(encryptedText);
        if (trimmedText == null || !trimmedText.startsWith(PREFIX)) {
            return encryptedText;
        }

        return decryptText(trimmedText.replaceFirst(REGEX_PREFIX, ""));
    }

    public EncryptedTextBuilder withCipher(String cipher) {
        this.cipher = cipher;
        return this;
    }

    public EncryptedTextBuilder withSalt(String salt) {
        this.salt = salt;
        return this;
    }

    public EncryptedTextBuilder withIterationCount(int iterationCount) {
        this.iterationCount = iterationCount;
        return this;
    }

    public EncryptedTextBuilder withKeyStrength(int keyStrength) {
        this.keyStrength = keyStrength;
        return this;
    }

    public EncryptedTextBuilder withSystemPropertySecret(String systemPropertySecret) {
        this.systemPropertySecret = systemPropertySecret;
        return this;
    }

    // ************************************************************************
    // Utility

    public String decryptText(String encryptedText) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {

        byte[] encryptedData = decode(encryptedText);
        byte[] iv = subArray(encryptedData, 0, 16);
        byte[] encryptedBytes = subArray(encryptedData, iv.length, encryptedData.length);

        SecretKey secretKey = createSecretKey();

        Cipher dcipher = Cipher.getInstance(cipher == null ? DEFAULT_CIPHER : cipher);
        dcipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] utf8 = dcipher.doFinal(encryptedBytes);

        return new String(utf8, StandardCharsets.UTF_8);
    }

    private byte[] subArray(byte[] array, int beginIndex, int endIndex) {
        int length = endIndex - beginIndex;
        byte[] subarray = new byte[length];
        System.arraycopy(array, beginIndex, subarray, 0, length);
        return subarray;
    }

    private byte[] decode(CharSequence s) {
        int nChars = s.length();
        if (nChars % 2 != 0) {
            throw new IllegalArgumentException("Hex-encoded string must have an even number of characters");
        } else {
            byte[] result = new byte[nChars / 2];

            for (int i = 0; i < nChars; i += 2) {
                int msb = Character.digit(s.charAt(i), 16);
                int lsb = Character.digit(s.charAt(i + 1), 16);
                if (msb < 0 || lsb < 0) {
                    throw new IllegalArgumentException("Detected a Non-hex character at " + (i + 1) + " or " + (i + 2) + " position");
                }

                result[i / 2] = (byte) (msb << 4 | lsb);
            }

            return result;
        }
    }

    private SecretKey createSecretKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec keySpec = new PBEKeySpec(fetchPassphrase().toCharArray(),
                decode(salt == null ? DEFAULT_SALT : salt),
                iterationCount == null || iterationCount == 0 ? DEFAULT_ITERATION_COUNT : iterationCount,
                keyStrength == null || keyStrength == 0 ? DEFAULT_KEY_STRENGTH : keyStrength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey secretKey = factory.generateSecret(keySpec);
        return new SecretKeySpec(secretKey.getEncoded(), "AES");
    }

    private String fetchPassphrase() {
        String passphrase = System.getenv(systemPropertySecret);
        if (passphrase == null) {
            passphrase = System.getProperty(systemPropertySecret);
        }

        if (passphrase == null) {
            throw new IllegalStateException("No passphrase detected in environment for: " + systemPropertySecret);
        }

        return passphrase;
    }

}
