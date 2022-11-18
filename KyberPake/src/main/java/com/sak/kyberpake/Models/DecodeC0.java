package com.sak.kyberpake.Models;

public class DecodeC0 {
    private byte[] seed;
    private short[][] m;
    private byte[] cid;

    public byte[] getSeed() {
        return seed;
    }

    public short[][] getM() {
        return m;
    }

    public byte[] getCid() {
        return cid;
    }

    public DecodeC0(byte[] seed, short[][] m, byte[] cid) {
        this.seed = seed;
        this.m = m;
        this.cid = cid;
    }
}
