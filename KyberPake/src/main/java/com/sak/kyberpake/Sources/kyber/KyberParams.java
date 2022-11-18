package com.sak.kyberpake.Sources.kyber;

public final class KyberParams {
    public final static int KYBER_N = 256;
    public final static int KYBER_Q = 3329;
    public final static int KYBER_Q_INV = 62209;
    public final static int KYBER_SYMBYTES = 32;
    public final static int KYBER_POLYBYTES = 384;
    public final static int paramsETAK512 = 3;
    public final static int paramsETAK768K1024 = 2;
    public final static int KYBER_POLYBYTES512 = 2 * KYBER_POLYBYTES;
    public final static int KYBER_POLYBYTES768 = 3 * KYBER_POLYBYTES;
    public final static int KYBER_POLYBYTES1024 = 4 * KYBER_POLYBYTES;
    public final static int paramsPolyCompressedBytesK768 = 128;
    public final static int paramsPolyCompressedBytesK1024 = 160;
    public final static int paramsPolyvecCompressedBytesK512 = 2 * 320;
    public final static int paramsPolyvecCompressedBytesK768 = 3 * 320;
    public final static int paramsPolyvecCompressedBytesK1024 = 4 * 352;
    public final static int paramsIndcpaPublicKeyBytesK512 = KYBER_POLYBYTES512 + KYBER_SYMBYTES;
    public final static int paramsIndcpaPublicKeyBytesK768 = KYBER_POLYBYTES768 + KYBER_SYMBYTES;
    public final static int paramsIndcpaPublicKeyBytesK1024 = KYBER_POLYBYTES1024 + KYBER_SYMBYTES;
    public final static int paramsIndcpaSecretKeyBytesK512 = 2 * KYBER_POLYBYTES;
    public final static int paramsIndcpaSecretKeyBytesK768 = 3 * KYBER_POLYBYTES;
    public final static int paramsIndcpaSecretKeyBytesK1024 = 4 * KYBER_POLYBYTES;
    public final static int Kyber512SKBytes = KYBER_POLYBYTES512 + ((KYBER_POLYBYTES512 + KYBER_SYMBYTES) + 2 * KYBER_SYMBYTES);
    public final static int Kyber768SKBytes = KYBER_POLYBYTES768 + ((KYBER_POLYBYTES768 + KYBER_SYMBYTES) + 2 * KYBER_SYMBYTES);
    public final static int Kyber1024SKBytes = KYBER_POLYBYTES1024 + ((KYBER_POLYBYTES1024 + KYBER_SYMBYTES) + 2 * KYBER_SYMBYTES);
    public final static int KYBER_SSBYTES = 32;
}
