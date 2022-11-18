package com.sak.kyberpake.Sources.kyber;

import java.util.Arrays;


public final class ByteOps {

    public static long convertByteTo24BitUnsignedInt(byte[] x) {
        long r = (long) (x[0] & 0xFF);
        r = r | (long) ((long) (x[1] & 0xFF) << 8);
        r = r | (long) ((long) (x[2] & 0xFF) << 16);
        return r;
    }
    public static short barrettReduce(short a) {
        short t;
        long shift = (((long) 1) << 26);
        short v = (short) ((shift + (KyberParams.KYBER_Q / 2)) / KyberParams.KYBER_Q);
        t = (short) ((v * a) >> 26);
        t = (short) (t * KyberParams.KYBER_Q);
        return (short) (a - t);
    }
    public static short[] generateCBDPoly(byte[] buf, int paramsK) {
        long t, d;
        int a, b;
        short[] r = new short[KyberParams.KYBER_POLYBYTES];
        switch (paramsK) {
            case 2:
                for (int i = 0; i < KyberParams.KYBER_N / 4; i++) {
                    t = ByteOps.convertByteTo24BitUnsignedInt(Arrays.copyOfRange(buf, (3 * i), buf.length));
                    d = t & 0x00249249;
                    d = d + ((t >> 1) & 0x00249249);
                    d = d + ((t >> 2) & 0x00249249);
                    for (int j = 0; j < 4; j++) {
                        a = (short) ((d >> (6 * j + 0)) & 0x7);
                        b = (short) ((d >> (6 * j + KyberParams.paramsETAK512)) & 0x7);
                        r[4 * i + j] = (short) (a - b);
                    }
                }
                break;
            default:
                for (int i = 0; i < KyberParams.KYBER_N / 8; i++) {
                    t = ByteOps.convertByteTo32BitUnsignedInt(Arrays.copyOfRange(buf, (4 * i), buf.length));
                    d = t & 0x55555555;
                    d = d + ((t >> 1) & 0x55555555);
                    for (int j = 0; j < 8; j++) {
                        a = (short) ((d >> (4 * j + 0)) & 0x3);
                        b = (short) ((d >> (4 * j + KyberParams.paramsETAK768K1024)) & 0x3);
                        r[8 * i + j] = (short) (a - b);
                    }
                }
        }
        return r;
    }
    public static short conditionalSubQ(short a) {
        a = (short) (a - KyberParams.KYBER_Q);
        a = (short) (a + ((int) ((int) a >> 15) & KyberParams.KYBER_Q));
        return a;
    }
    public static short montgomeryReduce(long a) {
        short u = (short) (a * KyberParams.KYBER_Q_INV);
        int t = (int) (u * KyberParams.KYBER_Q);
        t = (int) (a - t);
        t >>= 16;
        return (short) t;
    }
    public static long convertByteTo32BitUnsignedInt(byte[] x) {
        long r = (long) (x[0] & 0xFF);
        r = r | (long) ((long) (x[1] & 0xFF) << 8);
        r = r | (long) ((long) (x[2] & 0xFF) << 16);
        r = r | (long) ((long) (x[3] & 0xFF) << 24);
        return r;
    }

}
