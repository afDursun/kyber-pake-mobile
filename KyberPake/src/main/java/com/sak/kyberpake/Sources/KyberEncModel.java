package com.sak.kyberpake.Sources;

public class KyberEncModel {
    private byte[] secretKey;
    private byte[] cipherText;

    public byte[] getSecretKey() {
        return secretKey;
    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public KyberEncModel(byte[] secretKey, byte[] cipherText) {
        this.secretKey = secretKey;
        this.cipherText = cipherText;
    }
}