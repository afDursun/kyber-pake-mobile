package com.sak.kyberpake.Sources.kyber;


final class UnpackedCipherText {

    private short[][] bp;
    private short[] v;

    public UnpackedCipherText() {

    }
    public short[][] getBp() {
        return bp;
    }

    public void setBp(short[][] bp) {
        this.bp = bp;
    }

    public short[] getV() {
        return v;
    }
    public void setV(short[] v) {
        this.v = v;
    }

}
