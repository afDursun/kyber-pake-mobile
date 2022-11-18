package com.sak;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import android.os.Build;
import android.os.Bundle;
import android.util.Log;

import com.sak.kyberpake.Models.PakeC0;
import com.sak.kyberpake.Models.PakeC1;
import com.sak.kyberpake.Models.PakeS0;
import com.sak.kyberpake.R;
import com.sak.kyberpake.Sources.KyberPake;

import java.security.SecureRandom;
import java.util.Arrays;

public class MainActivity extends AppCompatActivity {
    @RequiresApi(api = Build.VERSION_CODES.O)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        byte[] sid = new byte[32];
        byte[] cid = new byte[32];
        byte[] pw = new byte[32];

        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(sid);
        secureRandom.nextBytes(cid);
        secureRandom.nextBytes(pw);

        /* Pake C0 */
        PakeC0 c0 = KyberPake.pake_c0( cid, sid, pw);

        /* Pake S0 */
        PakeS0 s0 = KyberPake.pake_s0( c0.getSend(), c0.getGamma(), sid );

        /* Pake C1 */
        PakeC1 c1 = KyberPake.pake_c1( s0.getSend(), c0.getSk(), c0.getState_1() );

        /* Pake S1 */
        byte[] sharedeSecretKey_s1 =  KyberPake.pake_s1( c1.getK_3_c(), s0.getState());

        /* Output SessionKey */
        Log.d("KyberPAKE-C1.SessionKey", hex( c1.getSharedSecretKey() ));
        Log.d("KyberPAKE-S1.SessionKey", hex( sharedeSecretKey_s1 ));

    }

    @RequiresApi(api = Build.VERSION_CODES.N)
    public static double avg(long[] array) {
        return Arrays.stream(array).average().orElse(Double.NaN);
    }
    public static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte aByte : bytes) {
            result.append(String.format("%02x", aByte));
        }
        return result.toString();
    }
}