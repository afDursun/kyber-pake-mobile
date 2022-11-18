package com.sak.kyberpake.Sources.kyber;

import static com.sak.kyberpake.PakeParams.HASH_BYTES;
import static com.sak.kyberpake.PakeParams.ID_BYTES;
import static com.sak.kyberpake.PakeParams.PAKE_KEYBYTES;
import static com.sak.kyberpake.PakeParams.PAKE_SENDC0;
import static com.sak.kyberpake.PakeParams.SEED_BYTES;
import android.os.Build;
import android.util.Log;
import androidx.annotation.RequiresApi;
import com.github.aelstad.keccakj.core.KeccakSponge;
import com.github.aelstad.keccakj.fips202.Shake128;
import com.github.aelstad.keccakj.fips202.Shake256;
import com.sak.kyberpake.Models.PakeC0;

import java.util.Arrays;

public final class Indcpa {
    public static void generateUniform(KyberUniformRandom uniformRandom, byte[] buf, int bufl, int l) {

        short[] buf_short = new short[buf.length];
        for (int i = 0 ; i < buf_short.length ; i++){
            if(buf[i] < 0 ){
                buf_short[i] = (short) (buf[i]+ 256);
            }
            else{
                buf_short[i] = (short) (buf[i]);
            }
        }


        short[] uniformR = new short[KyberParams.KYBER_POLYBYTES];
        int d1;
        int d2;
        int uniformI = 0; // Always start at 0
        int j = 0;
        while ((uniformI < l) && ((j + 3) <= bufl)) {
            d1 = (int) (((((int) (buf_short[j] & 0xFF)) >> 0) | (((int) (buf_short[j + 1] & 0xFF)) << 8)) & 0xFFF);
            d2 = (int) (((((int) (buf_short[j + 1] & 0xFF)) >> 4) | (((int) (buf_short[j + 2] & 0xFF)) << 4)) & 0xFFF);
            j = j + 3;
            if (d1 < (int) KyberParams.KYBER_Q) {
                uniformR[uniformI] = (short) d1;
                uniformI++;
            }
            if (uniformI < l && d2 < (int) KyberParams.KYBER_Q) {
                uniformR[uniformI] = (short) d2;
                uniformI++;
            }
        }
        uniformRandom.setUniformI(uniformI);
        uniformRandom.setUniformR(uniformR);
    }


    public static UnpackedPublicKey unpackPublicKey(byte[] packedPublicKey, int paramsK) {
        UnpackedPublicKey unpackedKey = new UnpackedPublicKey();
        switch (paramsK) {
            case 2:
                unpackedKey.setPublicKeyPolyvec(Poly.polyVectorFromBytes(Arrays.copyOfRange(packedPublicKey, 0, KyberParams.KYBER_POLYBYTES512), paramsK));
                unpackedKey.setSeed(Arrays.copyOfRange(packedPublicKey, KyberParams.KYBER_POLYBYTES512, packedPublicKey.length));
                break;
            case 3:
                unpackedKey.setPublicKeyPolyvec(Poly.polyVectorFromBytes(Arrays.copyOfRange(packedPublicKey, 0, KyberParams.KYBER_POLYBYTES768), paramsK));
                unpackedKey.setSeed(Arrays.copyOfRange(packedPublicKey, KyberParams.KYBER_POLYBYTES768, packedPublicKey.length));
                break;
            default:
                unpackedKey.setPublicKeyPolyvec(Poly.polyVectorFromBytes(Arrays.copyOfRange(packedPublicKey, 0, KyberParams.KYBER_POLYBYTES1024), paramsK));
                unpackedKey.setSeed(Arrays.copyOfRange(packedPublicKey, KyberParams.KYBER_POLYBYTES1024, packedPublicKey.length));
        }
        return unpackedKey;
    }
    public static byte[] packPrivateKey(short[][] privateKey, int paramsK) {
        byte[] packedPrivateKey = Poly.polyVectorToBytes(privateKey, paramsK);
        return packedPrivateKey;
    }

    public static short[][] unpackPrivateKey(byte[] packedPrivateKey, int paramsK) {
        short[][] unpackedPrivateKey = Poly.polyVectorFromBytes(packedPrivateKey, paramsK);
        return unpackedPrivateKey;
    }
    public static byte[] packCiphertext(short[][] b, short[] v, int paramsK) {
        byte[] bCompress = Poly.compressPolyVector(b, paramsK);
        byte[] vCompress = Poly.compressPoly(v, paramsK);
        byte[] returnArray = new byte[bCompress.length + vCompress.length];
        System.arraycopy(bCompress, 0, returnArray, 0, bCompress.length);
        System.arraycopy(vCompress, 0, returnArray, bCompress.length, vCompress.length);
        return returnArray;
    }
    public static UnpackedCipherText unpackCiphertext(byte[] c, int paramsK) {
        UnpackedCipherText unpackedCipherText = new UnpackedCipherText();
        byte[] bpc;
        byte[] vc;
        switch (paramsK) {
            case 2:
                bpc = new byte[KyberParams.paramsPolyvecCompressedBytesK512];
                break;
            case 3:
                bpc = new byte[KyberParams.paramsPolyvecCompressedBytesK768];
                break;
            default:
                bpc = new byte[KyberParams.paramsPolyvecCompressedBytesK1024];
        }
        System.arraycopy(c, 0, bpc, 0, bpc.length);
        vc = new byte[c.length - bpc.length];
        System.arraycopy(c, bpc.length, vc, 0, vc.length);
        unpackedCipherText.setBp(Poly.decompressPolyVector(bpc, paramsK));
        unpackedCipherText.setV(Poly.decompressPoly(vc, paramsK));

        return unpackedCipherText;
    }

    public static byte[] generatePRFByteArray(int l, byte[] key, byte nonce) {
        byte[] hash = new byte[l];
        KeccakSponge xof = new Shake256();
        byte[] newKey = new byte[key.length + 1];
        System.arraycopy(key, 0, newKey, 0, key.length);
        newKey[key.length] = nonce;
        xof.getAbsorbStream().write(newKey);
        xof.getSqueezeStream().read(hash);
        return hash;
    }
    public static byte[] packPublicKey(short[][] publicKey, byte[] seed, int paramsK) {
        byte[] initialArray = Poly.polyVectorToBytes(publicKey, paramsK);
        //Log.d("AFD-AFD",Utils.hex(publicKey[1]));
        byte[] packedPublicKey;
        switch (paramsK) {
            case 2:
                packedPublicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK512];
                System.arraycopy(initialArray, 0, packedPublicKey, 0, initialArray.length);
                System.arraycopy(seed, 0, packedPublicKey, initialArray.length, seed.length);
                break;
            case 3:
                packedPublicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK768];
                System.arraycopy(initialArray, 0, packedPublicKey, 0, initialArray.length);
                System.arraycopy(seed, 0, packedPublicKey, initialArray.length, seed.length);
                break;
            default:
                packedPublicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK1024];
                System.arraycopy(initialArray, 0, packedPublicKey, 0, initialArray.length);
                System.arraycopy(seed, 0, packedPublicKey, initialArray.length, seed.length);
        }

        return packedPublicKey;
    }
    public static short[][][] generateMatrix(byte[] seed, boolean transposed, int paramsK) {
        short[][][] r = new short[paramsK][paramsK][256];
        byte[] buf = new byte[672];
        KyberUniformRandom uniformRandom = new KyberUniformRandom();
        KeccakSponge xof = new Shake128();
        for (int i = 0; i < paramsK; i++) {
            r[i] = Poly.generateNewPolyVector(paramsK);
            for (int j = 0; j < paramsK; j++) {
                xof.reset();
                xof.getAbsorbStream().write(seed);
                byte[] ij = new byte[2];
                if (transposed) {
                    ij[0] = (byte) i;
                    ij[1] = (byte) j;
                } else {
                    ij[0] = (byte) j;
                    ij[1] = (byte) i;
                }
                xof.getAbsorbStream().write(ij);
                xof.getSqueezeStream().read(buf);


                generateUniform(uniformRandom, Arrays.copyOfRange(buf, 0, 504), 504, KyberParams.KYBER_N);
                int ui = uniformRandom.getUniformI();
                r[i][j] = uniformRandom.getUniformR();
                while (ui < KyberParams.KYBER_N) {
                    generateUniform(uniformRandom, Arrays.copyOfRange(buf, 504, 672), 168, KyberParams.KYBER_N - ui);
                    int ctrn = uniformRandom.getUniformI();
                    short[] missing = uniformRandom.getUniformR();
                    for (int k = ui; k < KyberParams.KYBER_N; k++) {
                        r[i][j][k] = missing[k - ui];
                    }
                    ui = ui + ctrn;
                }
            }
        }
        return r;
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    public static PakeC0 generateKyberKeys(int paramsK, byte[] cid, byte[] sid, byte[] pw) {
        PakeC0 modelS0 = null;
        try {
            short[][] skpv = Poly.generateNewPolyVector(paramsK);
            short[][] pkpv = Poly.generateNewPolyVector(paramsK);
            byte[] mbytes;
            byte[] gammabytes;
            short[][] e = Poly.generateNewPolyVector(paramsK);
            byte[] send =  new byte[PAKE_SENDC0];;
            short[][] gamma = new short[2][KyberParams.KYBER_POLYBYTES];
            short[][] m;
            byte[] publicSeed = new byte[KyberParams.KYBER_SYMBYTES];
            byte[] noiseSeed = new byte[KyberParams.KYBER_SYMBYTES];

            byte[] state = new byte[HASH_BYTES+3] ;



            for(int i = 0; i< KyberParams.KYBER_SYMBYTES; i++){
                publicSeed[i] = 1;
                noiseSeed[i] = 1;
            }
            short[][][] a = generateMatrix(publicSeed, false, paramsK);

            byte nonce = (byte) 0;
            for (int i = 0; i < paramsK; i++) {
                skpv[i] = Poly.getNoisePoly(noiseSeed, nonce, paramsK);
                nonce = (byte) (nonce + (byte) 1);
            }
            for (int i = 0; i < paramsK; i++) {
                e[i] = Poly.getNoisePoly(noiseSeed, nonce, paramsK);
                nonce = (byte) (nonce + (byte) 1);
            }

            skpv = Poly.polyVectorNTT(skpv, paramsK);
            skpv = Poly.polyVectorReduce(skpv, paramsK);
            e = Poly.polyVectorNTT(e, paramsK);
            for (int i = 0; i < paramsK; i++) {
                short[] temp = Poly.polyVectorPointWiseAccMont(a[i], skpv, paramsK);
                pkpv[i] = Poly.polyToMont(temp);
            }

            pkpv = Poly.polyVectorAdd_1(pkpv, e, paramsK);

            try{
                gamma = hash_vec_frompw(pw,nonce);
                m = Poly.polyVectorAdd_1(pkpv, gamma, paramsK);


                for(int i = 0; i< 2; i++){
                    for (int j = 0; j < KyberParams.KYBER_N; j++){
                        gamma[i][j] = (short) (KyberParams.KYBER_Q - gamma[i][j]);
                    }
                }

                for (int i = 0; i < ID_BYTES; i++)
                {
                    state[i] = cid[i];
                    state[i + ID_BYTES] = sid[i];
                }


                mbytes = Poly.polyVectorToBytes(m,2);

                for (int i = 0; i < mbytes.length; i++)
                    state[i+2*ID_BYTES-1] =  mbytes[i];



                gammabytes = Poly.polyVectorToBytes(gamma,2);

                for (int i = 0; i < gammabytes.length; i++)
                    state[i+ (2*ID_BYTES) + mbytes.length + PAKE_KEYBYTES] = gammabytes[i];

                send = encode_c0(mbytes, sid, cid);
            }catch (Exception se){
                Log.d("AFD-AFD",se.toString() );
                for ( int i = 0 ; i < se.getStackTrace().length ; i++){
                    Log.d("AFD-AFD",se.getStackTrace()[i] +" ");
                }
            }

            pkpv = Poly.polyVectorReduce(pkpv, paramsK);

            modelS0 = new PakeC0(send,state,gamma,packPublicKey(pkpv, publicSeed, paramsK),packPrivateKey(skpv, paramsK));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return modelS0;
    }

    private static byte[] encode_c0(byte[] m, byte[] seed, byte[] cid) {
        byte[] r = new byte[PAKE_SENDC0];
        int i;

        for ( i = 0; i < m.length; i++)
            r[i] = m[i];

        for ( i = 0; i < SEED_BYTES; i++)
            r[i + m.length ] = seed[i];

        for ( i = 0; i < ID_BYTES; i++)
            r[m.length + SEED_BYTES + i] = cid[i];

        return r;
    }

    private static short[][] hash_vec_frompw(byte[] pw, byte nonce) {
        short[][] retvalue = new short[2][KyberParams.KYBER_POLYBYTES];
        int i;
        for(i = 0; i< 2;i++)
        {
            retvalue[i] = hash_pw(pw, (byte) ((byte)i));
        }

        return retvalue;
    }

    private static short[] hash_pw(byte[] pw, byte nonce) {
        short[] retvalue = new short[256];
        int SHAKE128_RATE = 168;
        int pos = 0, ctr = 0;
        short val;
        int nblocks=4;
        byte[] buf = new byte[SHAKE128_RATE*nblocks];
        int i;
        byte[] extseed = new byte[32+1];


        for(i=0;i<32;i++)
            extseed[i] = pw[i];
        extseed[32] = nonce;

        KeccakSponge xof = new Shake128();
        xof.getAbsorbStream().write(extseed);
        xof.getSqueezeStream().read(buf);

        short[] buf_short = new short[buf.length];
        for (i = 0 ; i < buf.length ; i++){
            if(buf[i] < 0 ){
                buf_short[i] = (short) (buf[i]+ 256);
            }
            else{
                buf_short[i] = (short) (buf[i]);
            }
        }


        //Log.d("AFD-AFD",Arrays.toString(buf_short));

        while(ctr < 256)
        {
            val = (short) ((buf_short[pos] | ((short) buf_short[pos+1] << 8)) & 0x1fff);
            if(val < KyberParams.KYBER_Q)
            {
                retvalue[ctr++] = val;
            }
            pos += 2;

            if(pos > SHAKE128_RATE*nblocks-2)
            {
                nblocks = 1;
                pos = 0;
            }
        }

        return retvalue;
    }

    public static byte[] encrypt(byte[] m, byte[] publicKey, byte[] coins, int paramsK) {
        short[][] sp = Poly.generateNewPolyVector(paramsK);
        short[][] ep = Poly.generateNewPolyVector(paramsK);
        short[][] bp = Poly.generateNewPolyVector(paramsK);
        UnpackedPublicKey unpackedPublicKey = unpackPublicKey(publicKey, paramsK);
        short[] k = Poly.polyFromData(m);
        short[][][] at = generateMatrix(Arrays.copyOfRange(unpackedPublicKey.getSeed(), 0, KyberParams.KYBER_SYMBYTES), true, paramsK);

        for (int i = 0; i < paramsK; i++) {
            sp[i] = Poly.getNoisePoly(coins, (byte) (i), paramsK);
            ep[i] = Poly.getNoisePoly(coins, (byte) (i + paramsK), 3);
        }

        short[] epp = Poly.getNoisePoly(coins, (byte) (paramsK * 2), 3);
        sp = Poly.polyVectorNTT(sp, paramsK);
        sp = Poly.polyVectorReduce(sp, paramsK);
        for (int i = 0; i < paramsK; i++) {
            bp[i] = Poly.polyVectorPointWiseAccMont(at[i], sp, paramsK);
        }
        short[] v = Poly.polyVectorPointWiseAccMont(unpackedPublicKey.getPublicKeyPolyvec(), sp, paramsK);
        bp = Poly.polyVectorInvNTTMont(bp, paramsK);
        v = Poly.polyInvNTTMont(v);
        bp = Poly.polyVectorAdd(bp, ep, paramsK);
        v = Poly.polyAdd(Poly.polyAdd(v, epp), k);
        bp = Poly.polyVectorReduce(bp, paramsK);

        return packCiphertext(bp, Poly.polyReduce(v), paramsK);
    }
    public static byte[] decrypt(byte[] packedCipherText, byte[] privateKey, int paramsK) {
        UnpackedCipherText unpackedCipherText = unpackCiphertext(packedCipherText, paramsK);
        short[][] bp = unpackedCipherText.getBp();
        short[] v = unpackedCipherText.getV();
        short[][] unpackedPrivateKey = unpackPrivateKey(privateKey, paramsK);
        bp = Poly.polyVectorNTT(bp, paramsK);
        short[] mp = Poly.polyVectorPointWiseAccMont(unpackedPrivateKey, bp, paramsK);
        mp = Poly.polyInvNTTMont(mp);
        mp = Poly.polySub(v, mp);
        mp = Poly.polyReduce(mp);
        return Poly.polyToMsg(mp);
    }
}
