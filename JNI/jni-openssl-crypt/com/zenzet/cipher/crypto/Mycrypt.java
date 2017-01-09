package com.zenzet.cipher.crypto;
import java.util.*;

public class Mycrypt
{
    static { System.loadLibrary("jnicrypt");}

    public native static void LOCKetAESCFB();
    public native static Map<String, String> LKTGenerateKeyPair(int keyBytes);
    public native static long getInstance(String algor);
    public native static int digestUpdate(long ctx, byte[] in);
    public native static byte [] digestFinal(long ctx);

    public static void main (String[] args)
    {
        //LOCKetAESCFB ();
        /*
        Object object = Mycrypt.LKTGenerateKeyPair (4096);
        Map<String, String>map=(Map<String, String>)object;
        System.out.println("[java]pk:"+map.get("pk"));
        System.out.println("[java]pv:"+map.get("pv"));
        */

        long ctx = getInstance ("MD5");
        System.out.println("ctx" + ctx);

        byte [] input = {'h', 'e'};
        byte [] input2 = {'l', 'l', 'o'};

        digestUpdate(ctx, input);
        digestUpdate(ctx, input2);
        
        byte[] a = digestFinal (ctx);
        System.out.println (a);

    }

}
