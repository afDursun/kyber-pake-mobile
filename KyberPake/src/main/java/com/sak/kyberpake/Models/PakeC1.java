package com.sak.kyberpake.Models;

public class PakeC1 {
    byte[] k_3_c,sharedSecretKey;

    public byte[] getK_3_c() {
        return k_3_c;
    }

    public byte[] getSharedSecretKey() {
        return sharedSecretKey;
    }

    public PakeC1(byte[] k_3_c, byte[] sharedSecretKey) {
        this.k_3_c = k_3_c;
        this.sharedSecretKey = sharedSecretKey;
    }
}
