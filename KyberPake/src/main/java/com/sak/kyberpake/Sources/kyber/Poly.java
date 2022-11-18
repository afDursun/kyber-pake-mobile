package com.sak.kyberpake.Sources.kyber;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
public final class Poly {

    public static byte[] polyToBytes(short[] a) {
        int t0, t1;
        byte[] r = new byte[KyberParams.KYBER_POLYBYTES];
        a = Poly.polyConditionalSubQ(a);
        for (int i = 0; i < KyberParams.KYBER_N / 2; i++) {
            t0 = ((int) (a[2 * i] & 0xFFFF));
            t1 = ((int) (a[2 * i + 1]) & 0xFFFF);
            r[3 * i + 0] = (byte) (t0 >> 0);
            r[3 * i + 1] = (byte) ((int) (t0 >> 8) | (int) (t1 << 4));
            r[3 * i + 2] = (byte) (t1 >> 4);
        }

        return r;
    }
    public static short[] polyFromBytes(byte[] a) {
        short[] r = new short[KyberParams.KYBER_POLYBYTES];
        for (int i = 0; i < KyberParams.KYBER_N / 2; i++) {
            r[2 * i] = (short) ((((a[3 * i + 0] & 0xFF) >> 0) | ((a[3 * i + 1] & 0xFF) << 8)) & 0xFFF);
            r[2 * i + 1] = (short) ((((a[3 * i + 1] & 0xFF) >> 4) | ((a[3 * i + 2] & 0xFF) << 4)) & 0xFFF);
        }
        return r;
    }

    public static short[] polyFromData(byte[] msg) {
        short[] r = new short[KyberParams.KYBER_N];
        short mask;
        for (int i = 0; i < KyberParams.KYBER_N / 8; i++) {
            for (int j = 0; j < 8; j++) {
                mask = (short) (-1 * (short) (((msg[i] & 0xFF) >> j) & 1));
                r[8 * i + j] = (short) (mask & (short) ((KyberParams.KYBER_Q + 1) / 2));
            }
        }
        return r;
    }
    public static byte[] polyToMsg(short[] a) {
        byte[] msg = new byte[KyberParams.KYBER_SYMBYTES];
        int t;
        a = polyConditionalSubQ(a);
        for (int i = 0; i < KyberParams.KYBER_N / 8; i++) {
            msg[i] = 0;
            for (int j = 0; j < 8; j++) {
                t = (int) ((((((int) (a[8 * i + j])) << 1) + (KyberParams.KYBER_Q / 2)) / KyberParams.KYBER_Q) & 1);
                msg[i] = (byte) (msg[i] | (t << j));
            }
        }
        return msg;
    }
    protected short[] poly = new short[KyberParams.KYBER_POLYBYTES];
    protected short[][] polyvec;


    public static byte[] compressPoly(short[] polyA, int paramsK) {
        byte[] t = new byte[8];
        polyA = Poly.polyConditionalSubQ(polyA);
        int rr = 0;
        byte[] r;
        switch (paramsK) {
            case 2:
            case 3:
                r = new byte[KyberParams.paramsPolyCompressedBytesK768];
                for (int i = 0; i < KyberParams.KYBER_N / 8; i++) {
                    for (int j = 0; j < 8; j++) {
                        t[j] = (byte) (((((polyA[8 * i + j]) << 4) + (KyberParams.KYBER_Q / 2)) / (KyberParams.KYBER_Q)) & 15);
                    }
                    r[rr + 0] = (byte) (t[0] | (t[1] << 4));
                    r[rr + 1] = (byte) (t[2] | (t[3] << 4));
                    r[rr + 2] = (byte) (t[4] | (t[5] << 4));
                    r[rr + 3] = (byte) (t[6] | (t[7] << 4));
                    rr = rr + 4;
                }
                break;
            default:
                r = new byte[KyberParams.paramsPolyCompressedBytesK1024];
                for (int i = 0; i < KyberParams.KYBER_N / 8; i++) {
                    for (int j = 0; j < 8; j++) {
                        t[j] = (byte) (((((polyA[8 * i + j]) << 5) + (KyberParams.KYBER_Q / 2)) / (KyberParams.KYBER_Q)) & 31);
                    }
                    r[rr + 0] = (byte) ((t[0] >> 0) | (t[1] << 5));
                    r[rr + 1] = (byte) ((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
                    r[rr + 2] = (byte) ((t[3] >> 1) | (t[4] << 4));
                    r[rr + 3] = (byte) ((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
                    r[rr + 4] = (byte) ((t[6] >> 2) | (t[7] << 3));
                    rr = rr + 5;
                }
        }

        return r;
    }
    public static short[] decompressPoly(byte[] a, int paramsK) {
        short[] r = new short[KyberParams.KYBER_POLYBYTES];
        int aa = 0;
        switch (paramsK) {
            case 2:
            case 3:
                for (int i = 0; i < KyberParams.KYBER_N / 2; i++) {
                    r[2 * i + 0] = (short) (((((int) (a[aa] & 0xFF) & 15) * KyberParams.KYBER_Q) + 8) >> 4);
                    r[2 * i + 1] = (short) (((((int) (a[aa] & 0xFF) >> 4) * KyberParams.KYBER_Q) + 8) >> 4);
                    aa = aa + 1;
                }
                break;
            default:
                long[] t = new long[8];
                for (int i = 0; i < KyberParams.KYBER_N / 8; i++) {
                    t[0] = (long) ((int) (a[aa + 0] & 0xFF) >> 0) & 0xFF;
                    t[1] = (long) ((byte) (((int) (a[aa + 0] & 0xFF) >> 5)) | (byte) ((int) (a[aa + 1] & 0xFF) << 3)) & 0xFF;
                    t[2] = (long) ((int) (a[aa + 1] & 0xFF) >> 2) & 0xFF;
                    t[3] = (long) ((byte) (((int) (a[aa + 1] & 0xFF) >> 7)) | (byte) ((int) (a[aa + 2] & 0xFF) << 1)) & 0xFF;
                    t[4] = (long) ((byte) (((int) (a[aa + 2] & 0xFF) >> 4)) | (byte) ((int) (a[aa + 3] & 0xFF) << 4)) & 0xFF;
                    t[5] = (long) ((int) (a[aa + 3] & 0xFF) >> 1) & 0xFF;
                    t[6] = (long) ((byte) (((int) (a[aa + 3] & 0xFF) >> 6)) | (byte) ((int) (a[aa + 4] & 0xFF) << 2)) & 0xFF;
                    t[7] = ((long) ((int) (a[aa + 4] & 0xFF) >> 3)) & 0xFF;
                    aa = aa + 5;
                    for (int j = 0; j < 8; j++) {
                        r[8 * i + j] = (short) ((((long) (t[j] & 31) * (KyberParams.KYBER_Q)) + 16) >> 5);
                    }
                }
        }
        return r;
    }
    public static short[] getNoisePoly(byte[] seed, byte nonce, int paramsK) {
        int l;
        byte[] p;
        switch (paramsK) {
            case 2:
                l = KyberParams.paramsETAK512 * KyberParams.KYBER_N / 4;
                break;
            default:
                l = KyberParams.paramsETAK768K1024 * KyberParams.KYBER_N / 4;
        }

        p = Indcpa.generatePRFByteArray(l, seed, nonce);
        return ByteOps.generateCBDPoly(p, paramsK);
    }
    public static short[] polyNTT(short[] r) {
        return Ntt.ntt(r);
    }

    public static short[] polyInvNTTMont(short[] r) {
        return Ntt.invNTT(r);
    }

    public static short[] polyBaseMulMont(short[] polyA, short[] polyB) {
        for (int i = 0; i < KyberParams.KYBER_N / 4; i++) {
            short[] rx = Ntt.baseMultiplier(
                    polyA[4 * i + 0], polyA[4 * i + 1],
                    polyB[4 * i + 0], polyB[4 * i + 1],
                    (short) Ntt.nttZetas[64 + i]
            );
            short[] ry = Ntt.baseMultiplier(
                    polyA[4 * i + 2], polyA[4 * i + 3],
                    polyB[4 * i + 2], polyB[4 * i + 3],
                    (short) (-1 * Ntt.nttZetas[64 + i])
            );
            polyA[4 * i + 0] = rx[0];
            polyA[4 * i + 1] = rx[1];
            polyA[4 * i + 2] = ry[0];
            polyA[4 * i + 3] = ry[1];
        }
        return polyA;
    }
    public static short[] polyToMont(short[] polyR) {
        for (int i = 0; i < KyberParams.KYBER_N; i++) {
            polyR[i] = ByteOps.montgomeryReduce((long) (polyR[i] * 1353));
        }
        return polyR;
    }
    public static short[] polyReduce(short[] r) {
        for (int i = 0; i < KyberParams.KYBER_N; i++) {
            r[i] = ByteOps.barrettReduce(r[i]);
        }
        return r;
    }

    public static short[][] decompressPolyVector(byte[] a, int paramsK) {
        short[][] r = new short[paramsK][KyberParams.KYBER_POLYBYTES];
        int aa = 0;
        int[] t;
        switch (paramsK) {
            case 2:
            case 3:
                t = new int[4]; // has to be unsigned..
                for (int i = 0; i < paramsK; i++) {
                    for (int j = 0; j < (KyberParams.KYBER_N / 4); j++) {
                        t[0] = ((a[aa + 0] & 0xFF) >> 0) | ((a[aa + 1] & 0xFF) << 8);
                        t[1] = ((a[aa + 1] & 0xFF) >> 2) | ((a[aa + 2] & 0xFF) << 6);
                        t[2] = ((a[aa + 2] & 0xFF) >> 4) | ((a[aa + 3] & 0xFF) << 4);
                        t[3] = ((a[aa + 3] & 0xFF) >> 6) | ((a[aa + 4] & 0xFF) << 2);
                        aa = aa + 5;
                        for (int k = 0; k < 4; k++) {
                            r[i][4 * j + k] = (short) (((long) (t[k] & 0x3FF) * (long) (KyberParams.KYBER_Q) + 512) >> 10);
                        }
                    }
                }
                break;
            default:
                t = new int[8]; // has to be unsigned..
                for (int i = 0; i < paramsK; i++) {
                    for (int j = 0; j < (KyberParams.KYBER_N / 8); j++) {
                        t[0] = (((a[aa + 0] & 0xff) >> 0) | ((a[aa + 1] & 0xff) << 8));
                        t[1] = (((a[aa + 1] & 0xff) >> 3) | ((a[aa + 2] & 0xff) << 5));
                        t[2] = (((a[aa + 2] & 0xff) >> 6) | ((a[aa + 3] & 0xff) << 2) | ((a[aa + 4] & 0xff) << 10));
                        t[3] = (((a[aa + 4] & 0xff) >> 1) | ((a[aa + 5] & 0xff) << 7));
                        t[4] = (((a[aa + 5] & 0xff) >> 4) | ((a[aa + 6] & 0xff) << 4));
                        t[5] = (((a[aa + 6] & 0xff) >> 7) | ((a[aa + 7] & 0xff) << 1) | ((a[aa + 8] & 0xff) << 9));
                        t[6] = (((a[aa + 8] & 0xff) >> 2) | ((a[aa + 9] & 0xff) << 6));
                        t[7] = (((a[aa + 9] & 0xff) >> 5) | ((a[aa + 10] & 0xff) << 3));
                        aa = aa + 11;
                        for (int k = 0; k < 8; k++) {
                            r[i][8 * j + k] = (short) (((long) (t[k] & 0x7FF) * (long) (KyberParams.KYBER_Q) + 1024) >> 11);
                        }
                    }
                }
        }
        return r;
    }



    public static short[] poly_frombytes(byte[] a_prime) {
        short[] shorts = new short[KyberParams.KYBER_POLYBYTES];
        ByteBuffer.wrap(a_prime).order(ByteOrder.LITTLE_ENDIAN).asShortBuffer().get(shorts);
        return shorts;
    }

    public static short[][] polyVectorFromBytes(byte[] polyA, int paramsK) {
        short[][] r = new short[paramsK][KyberParams.KYBER_POLYBYTES];
        for (int i = 0; i < paramsK; i++) {
            int start = (i * KyberParams.KYBER_POLYBYTES);
            int end = (i + 1) * KyberParams.KYBER_POLYBYTES;
            r[i] = Poly.polyFromBytes(Arrays.copyOfRange(polyA, start, end));
        }
        return r;
    }

    public static short[][] polyVectorNTT(short[][] r, int paramsK) {
        for (int i = 0; i < paramsK; i++) {
            r[i] = Poly.polyNTT(r[i]);
        }
        return r;
    }
    public static short[][] polyVectorInvNTTMont(short[][] r, int paramsK) {
        for (int i = 0; i < paramsK; i++) {
            r[i] = Poly.polyInvNTTMont(r[i]);
        }
        return r;
    }
    public static byte[] polyVectorToBytes(short[][] polyA, int paramsK) {
        byte[] r = new byte[paramsK * KyberParams.KYBER_POLYBYTES];
        for (int i = 0; i < paramsK; i++) {
            byte[] byteA = polyToBytes(polyA[i]);
            System.arraycopy(byteA, 0, r, i * KyberParams.KYBER_POLYBYTES, byteA.length);
        }
        return r;
    }

    public static short[] polyVectorPointWiseAccMont(short[][] polyA, short[][] polyB, int paramsK) {
        short[] r = Poly.polyBaseMulMont(polyA[0], polyB[0]);
        for (int i = 1; i < paramsK; i++) {
            short[] t = Poly.polyBaseMulMont(polyA[i], polyB[i]);
            r = Poly.polyAdd(r, t);
        }
        return polyReduce(r);
    }
    public static short[][] polyVectorReduce(short[][] r, int paramsK) {
        for (int i = 0; i < paramsK; i++) {
            r[i] = Poly.polyReduce(r[i]);
        }
        return r;
    }
    public static short[][] polyVectorCSubQ(short[][] r, int paramsK) {
        for (int i = 0; i < paramsK; i++) {
            r[i] = Poly.polyConditionalSubQ(r[i]);
        }
        return r;
    }
    public static short[][] polyVectorAdd(short[][] polyA, short[][] polyB, int paramsK) {
        for (int i = 0; i < paramsK; i++) {
            polyA[i] = Poly.polyAdd(polyA[i], polyB[i]);
        }
        return polyA;
    }
    public static short[][] polyVectorAdd_1(short[][] polyA, short[][] polyB, int paramsK) {
        short[][] ret = new short[2][KyberParams.KYBER_POLYBYTES];
        for (int i = 0; i < paramsK; i++) {
            ret[i] = Poly.polyAdd_1(polyA[i], polyB[i]);
        }
        return ret;
    }
    public static short[] polyConditionalSubQ(short[] r) {
        for (int i = 0; i < KyberParams.KYBER_N; i++) {
            r[i] = ByteOps.conditionalSubQ(r[i]);
        }
        return r;
    }
    public static short[] polyAdd(short[] polyA, short[] polyB) {
        for (int i = 0; i < KyberParams.KYBER_N; i++) {
            polyA[i] = (short) (polyA[i] + polyB[i]);
        }
        return polyA;
    }
    public static short[] polyAdd_1(short[] polyA, short[] polyB) {
        short[] retValue = new short[KyberParams.KYBER_POLYBYTES];
        for (int i = 0; i < KyberParams.KYBER_N; i++) {
            if((short) (polyA[i] + polyB[i] ) < 0){
                //retValue[i] = (short) ((polyA[i] + polyB[i]) % KyberParams.paramsQ);
                retValue[i] = (short) Math.floorMod(polyA[i] + polyB[i] , KyberParams.KYBER_Q);
            }
            else{
                retValue[i] = (short) ((short) (polyA[i] + polyB[i]) % KyberParams.KYBER_Q);
            }
            //retValue[i] = (short) (polyA[i] + polyB[i]);
        }
        return retValue;
    }
    public static short[] polySub(short[] polyA, short[] polyB) {
        for (int i = 0; i < KyberParams.KYBER_N; i++) {
            polyA[i] = (short) (polyA[i] - polyB[i]);
        }
        return polyA;
    }
    public static short[][] generateNewPolyVector(int paramsK) {
        short[][] pv = new short[paramsK][256];
        return pv;
    }
    public static byte[] compressPolyVector(short[][] a, int paramsK) {
        Poly.polyVectorCSubQ(a, paramsK);
        int rr = 0;
        byte[] r;
        long[] t;
        switch (paramsK) {
            case 2:
                r = new byte[KyberParams.paramsPolyvecCompressedBytesK512];
                break;
            case 3:
                r = new byte[KyberParams.paramsPolyvecCompressedBytesK768];
                break;
            default:
                r = new byte[KyberParams.paramsPolyvecCompressedBytesK1024];
        }

        switch (paramsK) {
            case 2:
            case 3:
                t = new long[4];
                for (int i = 0; i < paramsK; i++) {
                    for (int j = 0; j < KyberParams.KYBER_N / 4; j++) {
                        for (int k = 0; k < 4; k++) {
                            t[k] = ((long) (((long) ((long) (a[i][4 * j + k]) << 10) + (long) (KyberParams.KYBER_Q / 2)) / (long) (KyberParams.KYBER_Q)) & 0x3ff);
                        }
                        r[rr + 0] = (byte) (t[0] >> 0);
                        r[rr + 1] = (byte) ((t[0] >> 8) | (t[1] << 2));
                        r[rr + 2] = (byte) ((t[1] >> 6) | (t[2] << 4));
                        r[rr + 3] = (byte) ((t[2] >> 4) | (t[3] << 6));
                        r[rr + 4] = (byte) ((t[3] >> 2));
                        rr = rr + 5;
                    }
                }
                break;
            default:
                t = new long[8];
                for (int i = 0; i < paramsK; i++) {
                    for (int j = 0; j < KyberParams.KYBER_N / 8; j++) {
                        for (int k = 0; k < 8; k++) {
                            t[k] = ((long) (((long) ((long) (a[i][8 * j + k]) << 11) + (long) (KyberParams.KYBER_Q / 2)) / (long) (KyberParams.KYBER_Q)) & 0x7ff);
                        }
                        r[rr + 0] = (byte) ((t[0] >> 0));
                        r[rr + 1] = (byte) ((t[0] >> 8) | (t[1] << 3));
                        r[rr + 2] = (byte) ((t[1] >> 5) | (t[2] << 6));
                        r[rr + 3] = (byte) ((t[2] >> 2));
                        r[rr + 4] = (byte) ((t[2] >> 10) | (t[3] << 1));
                        r[rr + 5] = (byte) ((t[3] >> 7) | (t[4] << 4));
                        r[rr + 6] = (byte) ((t[4] >> 4) | (t[5] << 7));
                        r[rr + 7] = (byte) ((t[5] >> 1));
                        r[rr + 8] = (byte) ((t[5] >> 9) | (t[6] << 2));
                        r[rr + 9] = (byte) ((t[6] >> 6) | (t[7] << 5));
                        r[rr + 10] = (byte) ((t[7] >> 3));
                        rr = rr + 11;
                    }
                }
        }
        return r;
    }

}
