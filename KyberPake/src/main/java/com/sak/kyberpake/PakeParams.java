package com.sak.kyberpake;

import com.sak.kyberpake.Sources.kyber.KyberParams;

public class PakeParams {
    public static int ID_BYTES = 32;
    public static int SEED_BYTES = 32;
    public static int PAKE_KEYBYTES = 32;
    public static int MLWE_D = 2;
    public static int POLY_BYTES = 416 ;
    public static int HASH_BYTES =  (2*ID_BYTES ) + (3 * (4* KyberParams.KYBER_POLYBYTES)) + PAKE_KEYBYTES ;


    public static int PAKE_SENDC0 = ID_BYTES + KyberParams.KYBER_POLYBYTES512 + SEED_BYTES ;

}
