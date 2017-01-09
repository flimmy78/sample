/* Copyright (C) 2015-2016 HangZhou Zenzet Technology Co., Ltd.
 * All right reserved

 * File:crypto/locketaes.c
 * Author:guojianchuan/max
 * Date:2016-06-02

 */

/* system header */
#include <string.h>

/* 3rd project header */
#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/err.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/bn.h" // this is for the BN_new

/* my project header */
#include "com_zenzet_cipher_crypto_Mycrypt.h"

#define ERR_SUCCESS     1
#define ERR_FAILED      2

char* LOCKET_ERR_GetString (void)
{
    int static iInit = 0;

    /* 加载错误信息 */
    if (!iInit)
    {
        ERR_load_ERR_strings();
        //ERR_load_crypto_strings();
    }

    return ERR_error_string(ERR_get_error(),NULL);
}


/**
* @Function:LOCKET_CIPHER_AESCrypt
* @Author: guojianchuan/max
* @Date: 2016-06-02
* @Description: AES encrypt/decrypt
* @caution: Algo format: Algo-bitnum-mode eg:"AES-128-CFB",
*/
int LOCKET_CIPHER_AESCrypt(unsigned char *pucInput, int iInputLen, unsigned  char* pucKey, unsigned char* pucIv, unsigned char *pucOutput, int *pOutputLen)
{
    char *cryptMode = "AES-128-CFB";
    printf ("Encrypt Mode:%s\n", cryptMode);
    printf ("plainText:%s\n", (char*)pucInput);
    printf ("plainTextLen:%d\n", iInputLen);
    printf ("Key:%s\n", (char*)pucKey);
    printf ("Iv:%s\n", (char*)pucIv);
    int iErr = ERR_SUCCESS;
    const EVP_CIPHER *pstCipher = NULL;

    /* Check algo */
    pstCipher = EVP_get_cipherbyname(cryptMode);
    if (NULL == pstCipher)
    {
        printf ("EVP_get_cipherbyname failed\n");
        return iErr;
    }

    /* encrypt/decryt */
    EVP_CIPHER_CTX *pstCipherCtx = NULL;
    do
    {
        /* init context */
        pstCipherCtx = EVP_CIPHER_CTX_new ();
        if (NULL == pstCipherCtx)
        {
            iErr = ERR_FAILED;
            break;
        }

        /* init algo */
        iErr = EVP_CipherInit_ex(pstCipherCtx, pstCipher, NULL, pucKey, pucIv, 1);
        if (ERR_SUCCESS != iErr)
        {
            printf ("EVP_CipherInit_ex failed, %s\n", LOCKET_ERR_GetString ());
            break;
        }
        
        int iOutLen1       = 0;
        /* encrypt/decrypt */
        iErr = EVP_CipherUpdate(pstCipherCtx, pucOutput, &iOutLen1, pucInput, iInputLen);
        if (ERR_SUCCESS != iErr)
        {
            printf ("EVP_CipherUpdate failed\n");
            break;
        }
        
        int iOutLen2       = 0;
        iErr = EVP_CipherFinal_ex(pstCipherCtx, pucOutput + iOutLen1, &iOutLen2);
        if (ERR_SUCCESS != iErr)
        {
            printf ("EVP_CipherFinal_ex failed. \n");
            break;
        }
        
        *pOutputLen = iOutLen1 + iOutLen2;
    } while (0);

    /* don't forget cleanup */
    EVP_CIPHER_CTX_free (pstCipherCtx);
    return iErr;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    LOCKetAESCFB
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_LOCKetAESCFB (JNIEnv *env, jclass jo)
{

    int iErr = ERR_SUCCESS;
    unsigned char *pucInput = (unsigned char*) "hello,world";
    unsigned char *pucKey = (unsigned char*) "this is key";
    unsigned char *pucIv = (unsigned char*) "this is iv";
    unsigned char szOutput[128] = {0};
    int iOutputLen = 0;
    
    iErr =  LOCKET_CIPHER_AESCrypt(pucInput, strlen((char*)pucInput), pucKey, pucIv, szOutput, &iOutputLen);
    if (ERR_SUCCESS != iErr)
    {
        printf ("LOCKET_CIPHER_AESCrypt err\n");
    }

    printf ("cryptText:");
    int i = 0;
    for (;i < iOutputLen; i++)
    {
        printf ("%.2x", szOutput[i]);

    }
    printf ("(hex)\n");
    printf ("cryptTextLen:%d\n", iOutputLen);
    return;
}



/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    LKTGenerateKeyPair
 * Signature: (I)Ljava/util/Map;
 */
JNIEXPORT jobject JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_LKTGenerateKeyPair 
(JNIEnv *env, jclass jo, jint ji)
{
    jclass class_map = (*env)->FindClass(env, "java/util/HashMap");
    jmethodID map_init = (*env)->GetMethodID(env, class_map, "<init>", "()V");
    jobject Map = (*env)->NewObject(env, class_map, map_init, "");
    jmethodID Map_put = (*env)->GetMethodID(env, class_map, 
                                            "put", 
                                            "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");


	RSA *rsa            = NULL;
	int modulelen       = (int) ji ;
	int ret             = ERR_SUCCESS;
	BIGNUM *bn          = NULL;
	unsigned long e     = RSA_F4;
    EVP_PKEY *pstKey    = NULL;
    unsigned char *pBuf = NULL;
    int iBase64Len      = 0;
    BIO *bioPtr         = NULL;
    unsigned char *pucPublicKey  = NULL;

#if 0
    bioPtr = BIO_new_file("rsa_private_key.pem", "r");
    if(bioPtr ==NULL)
    {
        printf("%s\n", "open rsa_private_key.pem error");        
        return Map;        
    }
    RSA *pRSA = PEM_read_bio_RSAPrivateKey(bioPtr, NULL, NULL, NULL);
    if (pRSA==NULL){
        printf("%s\n","Reading of private key failed");
    }else{
        printf("%s\n","Reading of private key successful");
    }
    unsigned char *pp            = NULL;
    int size = i2d_RSA_PUBKEY (pRSA, NULL);
    pucPublicKey = pp = (unsigned char*) malloc (size);
    memset (pp, 0, size);
    //printf ("pucPublicKey:%p, &pucPublicKey:%p, pp:%p, &&pp:%p\n", pucPublicKey, &pucPublicKey, pp, &pp);

    int iPubKeyLen = i2d_RSA_PUBKEY(pRSA, &pp); //DER
    if (0 == iPubKeyLen)
    {
        ret = ERR_FAILED;
        printf ("i2d_RSAPublicKey, failed to create RSA public key\n");
    }
//printf ("pucPublicKey:%p, &pucPublicKey:%p, pp:%p, &&pp:%p\n", pucPublicKey, &pucPublicKey, pp, &pp);
    printf ("iPubKeyLen:%d\n", iPubKeyLen);
    pBuf = (unsigned char*) malloc (iPubKeyLen * 2);
    if (NULL == pBuf)
    {
        ret = ERR_FAILED;
        printf ("malloc failed\n");
    }
    iBase64Len = EVP_EncodeBlock(pBuf, pucPublicKey, iPubKeyLen);
    printf ("pBuf:%s\n", pBuf);

    return Map;
#endif 

    do 
    {
        /* init rsa big num */
        bn  = BN_new () ; 
        ret = BN_set_word (bn , e) ;
        if (ERR_SUCCESS != ret)
        {
            printf ("BN_set_word method goes wrong\n");
            break;
        }

        /* init rsa algorithm */
        rsa = RSA_new ();
        ret = RSA_generate_key_ex (rsa, modulelen, bn, NULL);
        if (ERR_SUCCESS != ret)
        {
            printf ("RSA_generate_key_ex method goes wrong\n");
            break;
        }

        /* init evp_pkey */
        pstKey = EVP_PKEY_new();
        if(NULL == pstKey)
        {
            ret = ERR_FAILED;
            printf ("EVP_PKEY_new failed\n");
            break;
        }
        ret = EVP_PKEY_assign_RSA(pstKey, rsa);
        if (ERR_SUCCESS != ret)
        {
            printf ("EVP_PKEY_assign_RSA failed.\n");
            break;
        }

        /* ------------create public key-------------------*/
        /* pkcs1 && DER format */
        //unsigned char *pucPublicKey = NULL;
        unsigned char *pp            = NULL;
        int size = i2d_RSA_PUBKEY(rsa, NULL);
        if (0 == size)
        {
            ret = ERR_FAILED;
            printf ("i2d_RSA_PUBKEY, failed to create RSA public key.\n");
            break;
        }
        pucPublicKey = pp = (unsigned char*) malloc (size);
        if (NULL == pucPublicKey)
        {
            ret = ERR_FAILED;
            printf ("malloc failed\n");
            break;
        }
        memset (pp, 0, size);

        int iPubKeyLen = i2d_RSA_PUBKEY(rsa, &pp); //DER, i2d_RSAPublicKey接口不是DER的
        printf ("iPubKeyLen:%d\n", iPubKeyLen);
        if (0 == iPubKeyLen)
        {
            ret = ERR_FAILED;
            printf ("i2d_RSA_PUBKEY, failed to create RSA public key\n");
            break;
        }

        pBuf = (unsigned char*) malloc (iPubKeyLen * 2);
        if (NULL == pBuf)
        {
            ret = ERR_FAILED;
            printf ("malloc failed\n");
            break;
        }
        memset (pBuf, 0, iPubKeyLen * 2);
        int iBase64Len = EVP_EncodeBlock(pBuf, pucPublicKey, iPubKeyLen);

        //printf ("pk:%s\n", pBuf);
        (*env)->CallObjectMethod(env, Map, Map_put, 
                                 (*env)->NewStringUTF(env,"pk"), 
                                 (*env)->NewStringUTF(env, (char*) pBuf));

        free (pBuf);
        pBuf = NULL;
        free (pucPublicKey);
        pucPublicKey = NULL;

        /* ------------create private key-------------------*/
        bioPtr = BIO_new (BIO_s_mem());
        if (NULL == bioPtr)
        {
            ret = ERR_FAILED;
            printf ("create mem bio failed.\n") ;
            break;
        }

        //ret = PEM_write_bio_RSAPrivateKey ( bioPtr , rsa ,NULL, NULL, 0,  NULL , NULL );
        /* pkcs8 && DER format */
        ret = i2d_PKCS8PrivateKey_bio(bioPtr, pstKey, NULL, NULL, 0, NULL, NULL);
        if (ERR_SUCCESS != ret)
        {
            printf ("failed write RSA private key into file\n") ;
            break;
        }

        /* get data from bio mem */
        BUF_MEM *bptr = NULL;
        ret = BIO_get_mem_ptr(bioPtr, &bptr);
        if ((ERR_SUCCESS != ret) || (NULL == bptr))
        {
            printf ("BIO_get_mem_ptr failed\n") ;
            break;
        }

        pBuf = (unsigned char*) malloc (bptr->length * 2);
        if (NULL == pBuf)
        {
            ret = ERR_FAILED;
            printf ("malloc failed\n");
            break;
        }
        memset (pBuf, 0, bptr->length * 2);

        iBase64Len = EVP_EncodeBlock(pBuf, (unsigned char*) bptr->data, bptr->length);

        (*env)->CallObjectMethod(env, Map, Map_put, 
                                (*env)->NewStringUTF(env,"pv"), 
                                (*env)->NewStringUTF(env, (char*) pBuf));

    } while (0);

    if (ERR_SUCCESS != ret)
    {
        free(pucPublicKey);
        free (pBuf);
        (*env)->CallObjectMethod(env, Map, Map_put, 
                                 (*env)->NewStringUTF(env,"pk"), 
                                 (*env)->NewStringUTF(env, "invalid pk"));
        (*env)->CallObjectMethod(env, Map, Map_put, 
                                (*env)->NewStringUTF(env,"pv"), 
                                (*env)->NewStringUTF(env, "invalid pv"));
        EVP_PKEY_free(pstKey);
        BIO_free_all (bioPtr); 
    }
    return Map;
}

/*
 * Class:     Java_com_zenzet_cipher_crypto_Mycrypt_getInstance
 * Method:    getInstance
 * Signature: (I)Ljava/util/Map;
 */
JNIEXPORT jlong JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_getInstance
(JNIEnv *env, jclass jo, jstring algor)
{
	const char *alg = NULL;
	unsigned int len;
	const EVP_MD *md;
    int iErr = ERR_SUCCESS;
    EVP_MD_CTX *pstDigestCtx = NULL;

    OpenSSL_add_all_algorithms ();
    do 
    {
        if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
            iErr = ERR_FAILED;
            printf ("invalid param\n");
            break;
        }
        if (!(md = EVP_get_digestbyname(alg))) {
            iErr = ERR_FAILED;
            printf ("EVP_get_digestbyname failed, alg:%s\n", alg);
            break;
        }

        pstDigestCtx = malloc (sizeof (EVP_MD_CTX));
        if (NULL == pstDigestCtx)
        {
            iErr = ERR_FAILED;
            printf ("malloc failed\n");
            break;
        }
        EVP_MD_CTX_init(pstDigestCtx);

        iErr = EVP_DigestInit_ex(pstDigestCtx,md, NULL);
        if (ERR_SUCCESS != iErr)
        {
            iErr = ERR_FAILED;
            printf ("EVP_DigestInit_ex failed.\n");
            break;
        }
    } while (0);

	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
    if (ERR_SUCCESS != iErr)
    {
        EVP_MD_CTX_cleanup (pstDigestCtx);
        free (pstDigestCtx);
        return (jlong) NULL;
    }
    return (jlong) pstDigestCtx;
}

/*
 * Class:     Java_com_zenzet_cipher_crypto_Mycrypt_digestUpdate
 * Method:    digestUpdate
 * Signature: (I)Ljava/util/Map;
 */
JNIEXPORT
jint JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_digestUpdate
(JNIEnv *env, jobject this, jlong ctx, jbyteArray in)
{
	jbyteArray ret = NULL;
	unsigned char *inbuf = NULL;
	size_t inlen;
	unsigned int len;
    int iErr = ERR_SUCCESS;

    EVP_MD_CTX* pstDigestCtx = (EVP_MD_CTX*) ctx;
    if (NULL == pstDigestCtx)
    {
        iErr = ERR_FAILED;
        printf ("invalid param\n");
        return iErr;
    }

    do 
    {
        if (!(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))) {
            iErr = ERR_FAILED;
            printf ("invalid param\n");
            break;
        }
        inlen = (size_t)(*env)->GetArrayLength(env, in);
        if (inlen <= 0) {
            iErr = ERR_FAILED;
            printf ("invalid param\n");
            break;
        }

        iErr = EVP_DigestUpdate(pstDigestCtx, inbuf, inlen);
        if (ERR_SUCCESS != iErr)
        {
            printf ("EVP_DigestUpdate failed\n");
            break;
        }
    } while (0);

	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
    if (ERR_SUCCESS != iErr)
    {
        EVP_MD_CTX_cleanup (pstDigestCtx);
    }

	return ERR_SUCCESS;
}

/*
 * Class:     Java_com_zenzet_cipher_crypto_Mycrypt_digestFinal
 * Method:    digestFinal
 * Signature: (I)Ljava/util/Map;
 */
JNIEXPORT jbyteArray JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_digestFinal
(JNIEnv *env, jobject this, jlong ctx)
{

	jbyteArray ret = NULL;
	unsigned char *outbuf = NULL;
	size_t outlen;
	unsigned int len;
    int iErr = ERR_SUCCESS;

    EVP_MD_CTX* pstDigestCtx = (EVP_MD_CTX*) ctx;
    if (NULL == pstDigestCtx)
    {
        printf ("invalid param\n");
        return  NULL;
    }

    do 
    {
        outlen = EVP_MD_size (EVP_MD_CTX_md(pstDigestCtx));
        if (!(outbuf = malloc(outlen))) {
            iErr = ERR_FAILED;
            printf ("malloc failed\n");
            break;
        }
        bzero(outbuf, outlen);

        iErr = EVP_DigestFinal_ex(pstDigestCtx, outbuf, (unsigned int*) &outlen);
        if (ERR_SUCCESS != iErr)
        {
            iErr = ERR_FAILED;
            printf ("EVP_DigestFinal_ex failed\n");
            break;
        }
        printf ("outlen:%lu\n", outlen);
        int i = 0; 
        for (i = 0 ; i < outlen; i++)
        {
            printf ("%02x", outbuf[i]);
        }
        printf ("\n");

        if (!(ret = (*env)->NewByteArray(env, outlen))) {
            iErr = ERR_FAILED;
            break;
        }

        (*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

    } while (0);

	if (outbuf) free(outbuf);
    EVP_MD_CTX_cleanup (pstDigestCtx);
    if (ERR_SUCCESS != iErr)
    {
        return NULL;
    }
	return ret;
}
