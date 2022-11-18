package com.sak.kyberpake.Sources.kyber;

public final class KyberUniformRandom {
    private short[] uniformR;
    private int uniformI = 0;
    public KyberUniformRandom() {
    }
    public void setUniformR(short[] uniformR) {
        this.uniformR = uniformR;
    }
    public void setUniformI(int uniformI) {
        this.uniformI = uniformI;
    }
    public int getUniformI() {
        return uniformI;
    }
    public short[] getUniformR() {
        return uniformR;
    }

}
