package com.sak.kyberpake.Models;

public class PakeC0 {
    private byte[] send,state_1;
    private short[][] gamma;
    private byte[] pk,sk;

    public void setSend(byte[] send) {
        this.send = send;
    }

    public void setState_1(byte[] state_1) {
        this.state_1 = state_1;
    }

    public void setGamma(short[][] gamma) {
        this.gamma = gamma;
    }

    public void setPk(byte[] pk) {
        this.pk = pk;
    }

    public void setSk(byte[] sk) {
        this.sk = sk;
    }

    public byte[] getSend() {
        return send;
    }

    public byte[] getState_1() {
        return state_1;
    }

    public short[][] getGamma() {
        return gamma;
    }

    public byte[] getPk() {
        return pk;
    }

    public byte[] getSk() {
        return sk;
    }

    public PakeC0(byte[] send, byte[] state_1, short[][] gamma, byte[] pk, byte[] sk) {
        this.send = send;
        this.state_1 = state_1;
        this.gamma = gamma;
        this.pk = pk;
        this.sk = sk;
    }
}
