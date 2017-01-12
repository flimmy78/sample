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
	public native static byte [] publicKeyEncrypt(String algor, byte [] in, byte [] publicKey);
	public native static long  OpenSslRSANativeCryptInitContext(int cryptMode, int padding, byte[] key);
	public native static byte [] OpenSslRSANativeCryptUpdate(long ctx, int mode, byte[] in);
	public native static byte [] OpenSslRSANativeCryptdoFinal(long ctx, int mode, byte[] in);
	public native static long  OpenSslRSANativeSignInitContext(String hashalg, byte[] key);
	public native static int   OpenSslRSANativeSignUpdate(long ctx, byte[] in);
	public native static byte [] OpenSslRSANativeSigndoFinal(long ctx);

	public native static long  OpenSslRSANativeVerifyInitContext(String hashalg, byte[] key);
	public native static int   OpenSslRSANativeVerifyUpdate(long ctx, byte[] in);
	public native static int   OpenSslRSANativeVerifydoFinal(long ctx, byte[] sign);
	//public native static long [] OpenSslRSANative_crypt_doFinal(int cryptMode, int padding, String key);
	//public native byte [] publicKeyDecrypt(String algor, byte [] in, byte [] privateKey);

    public static void main (String[] args)
    {
        //LOCKetAESCFB ();

        long ctx = 0;
        /*
        long ctx = getInstance ("MD5");
        System.out.println("ctx" + ctx);

        byte [] input = {'h', 'e'};
        byte [] input2 = {'l', 'l', 'o'};

        digestUpdate(ctx, input);
        digestUpdate(ctx, input2);
        
        byte[] a = digestFinal (ctx);
        System.out.println (a);
        */

        Object object = Mycrypt.LKTGenerateKeyPair (1024);
        Map<String, String>map=(Map<String, String>)object;
        String pubkey = map.get("pk");
        String privatekey = map.get("pv");
        System.out.println("[java]pk:"+map.get("pk"));
        System.out.println("[java]pv:"+map.get("pv"));

        /*
        byte[] sPubkey = pubkey.getBytes();
        ctx = OpenSslRSANativeCryptInitContext (0, 1,  sPubkey);
        System.out.println (ctx);

        String sinput = "hello,world";
        byte[] binput = sinput.getBytes();
        byte[] boutput = OpenSslRSANativeCryptdoFinal (ctx, 0, binput);
        String soutput = new String(boutput);
        System.out.println (soutput);

        byte[] sPrivateKey = privatekey.getBytes();
        long ctx1 = OpenSslRSANativeCryptInitContext (1, 1, sPrivateKey);
        System.out.println (ctx1);

        byte[] boutput1 = OpenSslRSANativeCryptdoFinal (ctx1, 1,boutput); 
        String soutput1 = new String(boutput1);
        System.out.println (soutput1);
        */

        String md = "SHA512";
        String in = "hello,world";
        byte[] bin = in.getBytes();

        byte[] sPrivateKey = privatekey.getBytes();
        long ctx2 = OpenSslRSANativeSignInitContext (md,  sPrivateKey);
        int ret = OpenSslRSANativeSignUpdate (ctx2, bin);
        byte[] boutput2 = OpenSslRSANativeSigndoFinal (ctx2);

         
        byte[] sPublicKey = pubkey.getBytes();
        long ctx3 = OpenSslRSANativeVerifyInitContext("SHA512", sPublicKey);
        ret = OpenSslRSANativeVerifyUpdate (ctx3, bin);

        //System.out.println ("boutput2 len :" +boutput2.length);
        ret = OpenSslRSANativeVerifydoFinal (ctx3, boutput2);
        System.out.println ("verify :" + ret);
        

    }

}
