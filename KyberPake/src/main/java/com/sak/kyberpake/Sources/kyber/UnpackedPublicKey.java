package com.sak.kyberpake.Sources.kyber;


final class UnpackedPublicKey {

    private short[][] publicKeyPolyvec;
    private byte[] seed;

    public UnpackedPublicKey() {

    }


    public short[][] getPublicKeyPolyvec() {
        return publicKeyPolyvec;
    }

    public void setPublicKeyPolyvec(short[][] publicKeyPolyvec) {
        this.publicKeyPolyvec = publicKeyPolyvec;
    }
    public byte[] getSeed() {
        return seed;
    }
    public void setSeed(byte[] seed) {
        this.seed = seed;
    }

}
