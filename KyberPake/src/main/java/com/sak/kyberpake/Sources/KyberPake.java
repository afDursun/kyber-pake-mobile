package com.sak.kyberpake.Sources;

import static com.sak.kyberpake.PakeParams.HASH_BYTES;
import static com.sak.kyberpake.PakeParams.ID_BYTES;
import static com.sak.kyberpake.PakeParams.PAKE_KEYBYTES;
import static com.sak.kyberpake.PakeParams.PAKE_SENDC0;
import static com.sak.kyberpake.PakeParams.SEED_BYTES;
import static com.sak.kyberpake.Sources.kyber.Indcpa.packPublicKey;

import android.os.Build;
import android.util.Log;

import androidx.annotation.RequiresApi;

import com.github.aelstad.keccakj.core.KeccakSponge;
import com.github.aelstad.keccakj.fips202.SHA3_256;
import com.github.aelstad.keccakj.fips202.Shake256;
import com.sak.kyberpake.Models.DecodeC0;
import com.sak.kyberpake.Models.DecodeS0;
import com.sak.kyberpake.Models.PakeC1;
import com.sak.kyberpake.Models.PakeS0;
import com.sak.kyberpake.Models.PakeC0;
import com.sak.kyberpake.Sources.kyber.Indcpa;
import com.sak.kyberpake.Sources.kyber.KyberParams;
import com.sak.kyberpake.Sources.kyber.Poly;

import java.security.*;
import java.util.Arrays;

public final class KyberPake {

    @RequiresApi(api = Build.VERSION_CODES.O)
    public static PakeC0 pake_c0(byte[] cid, byte[] sid, byte[] pw) {
        int paramsK = 2;
        PakeC0 modelS0 = null;
        SecureRandom random = new SecureRandom();
        try {
            random = SecureRandom.getInstanceStrong();
        } catch (Exception e) {
        }
        try {
            modelS0 = Indcpa.generateKyberKeys(paramsK, cid, sid, pw);

            byte[] packedPublicKey = modelS0.getPk();
            byte[] packedPrivateKey = modelS0.getSk();

            byte[] privateKeyFixedLength = new byte[KyberParams.Kyber512SKBytes];
            MessageDigest md = new SHA3_256();
            byte[] encodedHash = md.digest(packedPublicKey);
            byte[] pkh = new byte[encodedHash.length];
            System.arraycopy(encodedHash, 0, pkh, 0, encodedHash.length);
            byte[] rnd = new byte[KyberParams.KYBER_SYMBYTES];
            random.nextBytes(rnd);
            int offsetEnd = packedPrivateKey.length;
            System.arraycopy(packedPrivateKey, 0, privateKeyFixedLength, 0, offsetEnd);
            System.arraycopy(packedPublicKey, 0, privateKeyFixedLength, offsetEnd, packedPublicKey.length);
            offsetEnd = offsetEnd + packedPublicKey.length;
            System.arraycopy(pkh, 0, privateKeyFixedLength, offsetEnd, pkh.length);
            offsetEnd += pkh.length;
            System.arraycopy(rnd, 0, privateKeyFixedLength, offsetEnd, rnd.length);

            modelS0.setPk(packedPublicKey);
            modelS0.setSk(privateKeyFixedLength);


        } catch (Exception ex) {
            ex.printStackTrace();
            Log.d("AFD-AFD", ex.toString());
            for (int i = 0; i < ex.getStackTrace().length; i++) {
                Log.d("AFD-AFD", ex.getStackTrace()[i] + " ");
            }
        }
        return modelS0;
    }

    public static PakeS0 pake_s0(byte[] received, short[][] gamma, byte[] sid) {
        short[][] y_c = new short[2][KyberParams.KYBER_POLYBYTES];
        byte[] publicSeed = new byte[KyberParams.KYBER_SSBYTES];
        DecodeC0 decodeC0 = decode_c0(received);
        byte[] state = new byte[HASH_BYTES + 3];
        int counter = 0;
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < KyberParams.KYBER_POLYBYTES; j++) {
                if (decodeC0.getM()[i][j] > KyberParams.KYBER_Q) {
                    counter++;
                }
            }
        }
        if (counter == 0) {
            for (int i = 0; i < KyberParams.KYBER_SYMBYTES; i++) {
                publicSeed[i] = 1;
            }

            for (int i = 0; i < 2; i++)
                for (int j = 0; j < KyberParams.KYBER_N; j++)
                    y_c[i][j] = (short) ((decodeC0.getM()[i][j] + gamma[i][j]) % KyberParams.KYBER_Q);

            y_c = Poly.polyVectorReduce(y_c, 2);
            byte[] packedPublicKey = packPublicKey(y_c, publicSeed, 2);
            KyberEncModel key = KyberKEM.encrypt512(publicSeed, packedPublicKey);

            for (int i = 0; i < ID_BYTES; i++) {
                state[i] = decodeC0.getCid()[i];
                state[i + ID_BYTES] = sid[i];
            }


            byte[] mbytes = new byte[KyberParams.KYBER_POLYBYTES * 2];
            mbytes = Poly.polyVectorToBytes(decodeC0.getM(), 2);

            for (int i = 0; i < mbytes.length; i++)
                state[i + 2 * ID_BYTES - 1] = mbytes[i];


            byte[] gammabytes;
            byte[] pkBytes = Poly.polyVectorToBytes(y_c, 2);
            gammabytes = Poly.polyVectorToBytes(gamma, 2);
            for (int i = 0; i < gammabytes.length; i++)
                state[i + (2 * ID_BYTES) + mbytes.length + PAKE_KEYBYTES] = gammabytes[i];


     //       Log.d("AFD-AFD-S0",Arrays.toString(state));

            for (int i = 0; i < pkBytes.length; i++)
                state[i + 2 * ID_BYTES + mbytes.length + gammabytes.length] = pkBytes[i];

            for (int i = 0; i < PAKE_KEYBYTES; i++)
                state[i + 2 * ID_BYTES + mbytes.length + gammabytes.length + pkBytes.length] = key.getSecretKey()[i];


            byte[] k = new byte[32];
            KeccakSponge xof = new Shake256();
            xof.getAbsorbStream().write(state);
            xof.getSqueezeStream().read(k);

            byte[] send = new byte[PAKE_SENDC0];

            send = encode_s0(pkBytes, k, key.getCipherText());

            return new PakeS0(send, state, key.getSecretKey(), k);
        } else {
            Log.d("AFD-AFD", "111-takıldı");
            return null;
        }

    }

    public static PakeC1 pake_c1(byte[] received, byte[] sk, byte[] state) {
        DecodeS0 decodeS0 = decode_s0(received);

        int counter = 0;
        short[][] p_key;
        p_key = Poly.polyVectorFromBytes(decodeS0.getY_c(),2);



        //gama negative
        byte[] k = KyberKEM.decrypt512(decodeS0.getCipherText(), sk);


        for (int i = 0; i < decodeS0.getY_c().length; i++)
            state[i + 2 * ID_BYTES + 768+768] = decodeS0.getY_c()[i];
        for (int i = 0; i < PAKE_KEYBYTES; i++)
            state[i + 2 * ID_BYTES + 768+768+decodeS0.getY_c().length] = k[i];

        byte[] k_control = new byte[32];
        KeccakSponge xof = new Shake256();
        xof.getAbsorbStream().write(state);
        xof.getSqueezeStream().read(k_control);

        byte[] k_prime = new byte[32];
        byte[] sharedkey = new byte[32];

        state[HASH_BYTES] = 0;
        xof.getAbsorbStream().write(state);
        xof.getSqueezeStream().read(k_prime);
        state[HASH_BYTES + 1] = 1;

        xof.getAbsorbStream().write(state);
        xof.getSqueezeStream().read(sharedkey);

        return new PakeC1(k_prime, sharedkey);


    }

    public static byte[] pake_s1(byte[] k_3_c, byte[] state) {
        byte[] sharedkey = new byte[32];

        byte[] k_2_prime = new byte[32];
        KeccakSponge xof = new Shake256();
        xof.getAbsorbStream().write(state);
        xof.getSqueezeStream().read(k_2_prime);

        if (Arrays.equals(k_3_c, k_2_prime)) {
            state[HASH_BYTES + 1] = 1;
            xof.getAbsorbStream().write(state);
            xof.getSqueezeStream().read(sharedkey);
            return sharedkey;
        } else {
            Log.d("AFD-AFD", "333-takıldı");
            return null;
        }

    }

    //Decode&Encode
    private static byte[] encode_s0(byte[] y_c, byte[] k, byte[] cipherText) {
        byte[] send = new byte[y_c.length + k.length + cipherText.length];
        ;

        System.arraycopy(y_c, 0, send, 0, y_c.length);
        System.arraycopy(k, 0, send, y_c.length, k.length);
        System.arraycopy(cipherText, 0, send, (k.length + y_c.length), cipherText.length);


        return send;
    }

    private static DecodeS0 decode_s0(byte[] r) {
        return new DecodeS0(Arrays.copyOfRange(r, 0, 384 * 2), Arrays.copyOfRange(r, 384 * 2, (384 * 2 + 32)), Arrays.copyOfRange(r, (384 * 2 + 32), r.length));
    }

    private static DecodeC0 decode_c0(byte[] r) {

        byte[] seed = new byte[SEED_BYTES];
        byte[] cid = new byte[ID_BYTES];
        short[][] m = new short[2][256];

        int i;
        m = Poly.polyVectorFromBytes(r, 2);

        for (i = 0; i < SEED_BYTES; i++)
            seed[i] = r[i + 768];
        for (i = 0; i < ID_BYTES; i++)
            cid[i] = r[i + 768 + SEED_BYTES];


         return new DecodeC0(seed, m, cid);
    }
}
