package tech.skidonion.verification.utils;

import java.util.Base64;

public class Internals {
    private static byte[] NONCE;
    private static Object CRYPTO;
    private static String VERIFY_TOKEN;
    private static byte[] KEY;
    private static String USERNAME;
    private static long USER_ID;
    private static byte[] MAGIC_KEY;

    public static String verificationServer() {
        return "http://localhost:8694/";
    }

    public static byte[] publicKey() {
        return Base64.getDecoder().decode("MCowBQYDK2VwAyEAfZU0fSt8t0DWwlXSX4hF/TKN7NW+Z9CYy8/m3/Q5AAs=");
    }

    public static long softwareId() {
        return 1L;
    }

    public static void decryptClasses(int hash, byte[] key) {
    }

    public static byte[] sessionKey() {
        return new byte[16];
    }

    public static byte[] nonce() {
        return new byte[12];
    }

    public static String version() {
        return "";
    }

    public static void initBuffer() {
    }

    public static boolean shouldKeepAlive() {
        return true;
    }

    public static boolean shouldCheckHwid() {
        return true;
    }

    public static byte[] getNonce() {
        return NONCE;
    }

    public static void setNonce(byte[] NONCE) {
        Internals.NONCE = NONCE;
    }

    public static Object getCrypto() {
        return CRYPTO;
    }

    public static void setCrypto(Object CRYPTO) {
        Internals.CRYPTO = CRYPTO;
    }

    public static String getVerifyToken() {
        return VERIFY_TOKEN;
    }

    public static void setVerifyToken(String verifyToken) {
        Internals.VERIFY_TOKEN = verifyToken;
    }

    public static byte[] getKey() {
        return KEY;
    }

    public static void setKey(byte[] KEY) {
        Internals.KEY = KEY;
    }

    public static String getUsername() {
        return USERNAME;
    }

    public static void setUsername(String USERNAME) {
        Internals.USERNAME = USERNAME;
    }

    public static long getUserId() {
        return USER_ID;
    }

    public static void setUserId(long USER_ID) {
        Internals.USER_ID = USER_ID;
    }

    public static byte[] getMagicKey() {
        return MAGIC_KEY;
    }

    public static void setMagicKey(byte[] magicKey) {
        Internals.MAGIC_KEY = magicKey;
    }

}
