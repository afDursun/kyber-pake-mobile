package com.sak.kyberpake.Models;

public class DecodeS0 {
    private byte[] cipherText;
    private byte[] y_c;
    private byte[] k;

    public byte[] getCipherText() {
        return cipherText;
    }

    public byte[] getY_c() {
        return y_c;
    }

    public byte[] getK() {
        return k;
    }

    public DecodeS0(byte[] y_c, byte[] k, byte[] cipherText) {
        this.cipherText = cipherText;
        this.y_c = y_c;
        this.k = k;
    }
}
