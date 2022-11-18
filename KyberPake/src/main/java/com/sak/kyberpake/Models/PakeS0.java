package com.sak.kyberpake.Models;

public class PakeS0 {
    private byte[] send,state,k_3_s,kprime;

    public byte[] getSend() {
        return send;
    }

    public byte[] getState() {
        return state;
    }

    public byte[] getK_3_s() {
        return k_3_s;
    }

    public byte[] getKprime() {
        return kprime;
    }

    public PakeS0(byte[] send, byte[] state, byte[] k_3_s, byte[] kprime) {
        this.send = send;
        this.state = state;
        this.k_3_s = k_3_s;
        this.kprime = kprime;
    }
}
