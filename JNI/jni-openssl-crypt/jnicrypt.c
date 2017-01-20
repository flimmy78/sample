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

#define PRINT_ERROR(msg)  fprintf(stderr, "error:%s %s %d\n", msg, __FILE__, __LINE__)

typedef enum tagCryptMode
{
    ENCRYPT = 0,
    DECRYPT = 1
}CRYPTMODE;

typedef enum tagPaddingMode
{
    NO_PADDING = 0,
    PKCS1_PADDING = 1,
    PKCS1_OAEP_PADDING = 2
}PADDINGMODE;

typedef struct tagSignContext
{
    const EVP_MD* md;
    EVP_MD_CTX mdctx;
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *pkctx;
}SIGNCTX;

typedef struct tagRSAContext
{
    int cryptmode;
    int padding;
    EVP_PKEY_CTX *pkctx;
}RSACTX;

typedef struct tagSM2Context
{
    int cryptmode;
    EVP_PKEY_CTX *pkctx;
}SM2CTX;

char* LOCKET_ERR_GetString (void)
{
    int static iInit = 0;

    /* 加载错误信息 */
    if (!iInit)
    {
        ERR_load_ERR_strings();
        ERR_load_crypto_strings();
        iInit  = 1;
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

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    
 * Signature: (Ljava/lang/String;I[B[B)[B
 * Note:      padding 参考当前文件内定义的PADDINGMODE
 */
JNIEXPORT jlong JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslRSANativeCryptInitContext
  (JNIEnv *env, jclass this, jint algomode,  jint padding)
{
    (void) algomode;

    int iErr = ERR_SUCCESS;
    RSACTX *rsaContext = NULL;

    do 
    {
        rsaContext = (RSACTX*) malloc (sizeof (RSACTX));
        if (NULL == rsaContext)
        {
            PRINT_ERROR("malloc failed");
            iErr = ERR_FAILED;
            break;
        }

        rsaContext->padding = padding;

    } while (0);

    if (ERR_SUCCESS != iErr)
    {
        free(rsaContext);
    }

	return (jlong) rsaContext;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    publicKeyEncrypt
 * Signature: (Ljava/lang/String;I[B[B)[B
 * Note:      cryptmode, 参考当前文件内定义的CRYPTMODE
 */
JNIEXPORT jint JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslRSANativeCryptInit
  (JNIEnv *env, jclass this, jlong ctx, jint cryptmode, jbyteArray key)
{
	unsigned char *keybuf = NULL;
	size_t keylen = 0;
	const unsigned char *p = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;
    int iErr = ERR_SUCCESS;

    RSACTX *rsaContext = (RSACTX*) ctx;
    if (NULL == rsaContext)
    {
        PRINT_ERROR ("invalid ctx");
        return ERR_FAILED;
    }
    rsaContext->cryptmode = cryptmode;

    do 
    {
        if (NULL == key)
        {
            PRINT_ERROR ("invalid input ");
            iErr = ERR_FAILED;
            break;
        }

        if (!(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))) {
            PRINT_ERROR ("invalid key");
            iErr = ERR_FAILED;
            break;
        }

        keylen = (size_t)(*env)->GetArrayLength(env, key);
        if (keylen == 0)
        {
            PRINT_ERROR ("invalid key length");
            iErr = ERR_FAILED;
            break;
        }

        unsigned char szDecBase64Buf[keylen];
        int tmplen = EVP_DecodeBlock(szDecBase64Buf, keybuf, keylen);

        p = szDecBase64Buf;
        if (ENCRYPT == cryptmode)
        {
            if (!(pkey = d2i_PUBKEY(&pkey, &p, tmplen))) {
                PRINT_ERROR ("d2i_PUBKEY failed");
                iErr = ERR_FAILED;
                break;
            }
        }
        else
        {
            if (!(pkey = d2i_AutoPrivateKey(NULL, &p, tmplen))){
                PRINT_ERROR ("d2i_AutoPrivateKey failed");
                iErr = ERR_FAILED;
                break;
            }
        }

        if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
            PRINT_ERROR("EVP_PKEY_CTX_new failed");
            iErr = ERR_FAILED;
            break;
        }
        rsaContext->pkctx = pkctx;

        if (ENCRYPT == cryptmode)
        {
            if (!EVP_PKEY_encrypt_init(rsaContext->pkctx)) 
            {
                PRINT_ERROR("EVP_PKEY_encrypt_init failed");
                iErr = ERR_FAILED;
                break;
            }
        }
        else
        {
            if (!EVP_PKEY_decrypt_init(rsaContext->pkctx))
            {
                PRINT_ERROR("EVP_PKEY_decrypt_init failed");
                iErr = ERR_FAILED;
                break;
            }
        }

        int padding = rsaContext->padding;
        int rsapadding = 0;
        if (PKCS1_PADDING == padding)
        {
            rsapadding = RSA_PKCS1_PADDING;
        }
        else if (NO_PADDING == padding)
        {
            rsapadding = RSA_NO_PADDING;
        }
        else if (PKCS1_OAEP_PADDING == padding)
        {
            rsapadding = RSA_PKCS1_OAEP_PADDING;
        } 

        if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA) {
            if (!EVP_PKEY_CTX_set_rsa_padding(rsaContext->pkctx, rsapadding)){
                PRINT_ERROR("EVP_PKEY_CTX_set_rsa_padding failed");
                iErr = ERR_FAILED;
                break;
            }
        }
    } while (0);

    if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
    EVP_PKEY_free(pkey);

    if (ERR_SUCCESS != iErr)
    {
        EVP_PKEY_CTX_free(rsaContext->pkctx);
        free (rsaContext);
    }

	return iErr;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslRSANativeCryptUpdate
 * Signature: (J[B)[B
 */
static JNIEXPORT jbyteArray JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslRSANativeCryptUpdate
  (JNIEnv *env, jclass this, jlong ctx, jbyteArray in)
{
	jbyteArray ret = NULL;
	unsigned char *inbuf = NULL;
	unsigned char *outbuf = NULL;
	size_t inlen, outlen;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;
    int iErr = ERR_SUCCESS;

    RSACTX *rsaContext = (RSACTX*) ctx;
    if (NULL == rsaContext)
    {
        PRINT_ERROR ("invalid ctx");
        return NULL;
    }
    pkctx = rsaContext->pkctx;

    do 
    {
        if (NULL == in)
        {
            PRINT_ERROR ("invalid input ");
            iErr = ERR_FAILED;
            break;
        }

        if (!(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))) {
            PRINT_ERROR ("invalid input ");
            iErr = ERR_FAILED;
            break;
        }

        inlen = (size_t)(*env)->GetArrayLength(env, in);
        if (inlen <= 0) {
            PRINT_ERROR ("invalid in length");
            iErr = ERR_FAILED;
            break;
        }

        /* we can not get ciphertext length from plaintext
         * so malloc the max buffer
         */
        EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey (pkctx);
        RSA *rsa = EVP_PKEY_get1_RSA(pkey);
        
        outlen = RSA_size (rsa);
        if (!(outbuf = malloc(outlen))) {
            PRINT_ERROR("malloc failed");
            iErr = ERR_FAILED;
            break;
        }

        if (ENCRYPT == rsaContext->cryptmode)
        {
            if (!EVP_PKEY_encrypt(pkctx, outbuf, &outlen, inbuf, inlen)) {
                PRINT_ERROR("EVP_PKEY_encrypt failed");
                iErr = ERR_FAILED;
                break;
            }
        }
        else
        {
            if (!EVP_PKEY_decrypt(pkctx, outbuf, &outlen, inbuf, inlen)) {
                PRINT_ERROR("EVP_PKEY_decrypt failed");
                iErr = ERR_FAILED;
                break;
            }
        }

        if (!(ret = (*env)->NewByteArray(env, outlen))) {
            PRINT_ERROR("NewByteArray failed");
            iErr = ERR_FAILED;
            break;
        }

        (*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);
    } while (0);

    if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
    if (outbuf) free(outbuf);

    if (ERR_SUCCESS != iErr)
    {
        if (NULL != pkctx) EVP_PKEY_CTX_free(pkctx);
        free (rsaContext);
    }

	return ret;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslRSANativeCryptdoFinal
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslRSANativeCryptdoFinal
  (JNIEnv *env, jclass this, jlong ctx, jbyteArray in)
{
	jbyteArray ret = NULL;
    ret = Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslRSANativeCryptUpdate (env, this, ctx, in);
    if (NULL == ret)
    {
        return ret;
    }

    RSACTX *rsaContext = (RSACTX*) ctx;
    EVP_PKEY_CTX_free(rsaContext->pkctx);
    free (rsaContext);

    return ret;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslRSANativeSignInitContext
 * Signature: (Ljava/lang/String;[B)J
 * Note:      padding默认PKCS1,如有需要可以支持其他的
 */
JNIEXPORT jlong JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslRSANativeSignInitContext
  (JNIEnv *env , jclass this, jstring algor)
{
    SIGNCTX *signCtx = (SIGNCTX*) malloc (sizeof (SIGNCTX));
    if (NULL == signCtx)
    {
        return (jlong) NULL;
    }
    memset (signCtx, 0, sizeof (SIGNCTX));
    const char* alg = NULL;
	const unsigned char *p = NULL;
    int iErr = ERR_SUCCESS;
    OpenSSL_add_all_algorithms ();

    do
    {
        if (NULL == algor)
        {
            iErr = ERR_FAILED;
            PRINT_ERROR ("invalid input");
            break;
        }

        if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
            iErr = ERR_FAILED;
            PRINT_ERROR("invalid alg");
            break;
        }

        if (!(signCtx->md = EVP_get_digestbyname(alg))) {
            iErr = ERR_FAILED;
            printf ("EVP_get_digestbyname failed, alg:%s\n", alg);
            break;
        }

        EVP_MD_CTX_init(&signCtx->mdctx);
    } while (0);

	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);

    if (ERR_SUCCESS != iErr)
    {
        if (NULL != signCtx) free (signCtx);
        return (jlong) NULL;
    }

    return (jlong) signCtx;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslRSANativeSignInitContext
 * Signature: (Ljava/lang/String;[B)J
 * Note:      padding默认PKCS1,如有需要可以支持其他的
 */
JNIEXPORT jint JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslRSANativeSignInit
  (JNIEnv *env , jclass this, jlong ctx, jbyteArray key)
{
    SIGNCTX *signCtx = (SIGNCTX*) ctx;
    if (NULL == signCtx)
    {
        return (jlong) NULL;
    }

	const unsigned char *p = NULL;
    unsigned char *keybuf = NULL;
	unsigned int keylen = 0;
    int iErr = ERR_SUCCESS;
    OpenSSL_add_all_algorithms ();

    do
    {
        if (NULL == key)
        {
            iErr = ERR_FAILED;
            PRINT_ERROR ("invalid input");
            break;
        }

        if (!(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))) {
            PRINT_ERROR ("invalid key");
            iErr = ERR_FAILED;
            break;
        }

        keylen = (size_t)(*env)->GetArrayLength(env, key);
        if (keylen == 0)
        {
            PRINT_ERROR ("invalid key length");
            iErr = ERR_FAILED;
            break;
        }

        unsigned char szDecBase64Buf[keylen];
        int tmplen = EVP_DecodeBlock(szDecBase64Buf, keybuf, keylen);
        p = szDecBase64Buf;
        if (!(signCtx->pkey = d2i_AutoPrivateKey(NULL, &p, tmplen))){
            PRINT_ERROR ("d2i_AutoPrivateKey failed");
            iErr = ERR_FAILED;
            break;
        }

        if (!EVP_DigestSignInit(&signCtx->mdctx, &signCtx->pkctx, signCtx->md, NULL, signCtx->pkey))
        {
            iErr = ERR_FAILED;
            PRINT_ERROR("EVP_DigestSignInit failed.");
            break;
        }

        if (!EVP_PKEY_CTX_set_rsa_padding(signCtx->pkctx, RSA_PKCS1_PADDING)){
            PRINT_ERROR("EVP_PKEY_CTX_set_rsa_padding failed");
            iErr = ERR_FAILED;
            break;
        }

    } while (0);

    if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);

    if (ERR_SUCCESS != iErr)
    {
        if (NULL != signCtx->pkey) EVP_PKEY_free (signCtx->pkey);
        EVP_MD_CTX_cleanup (&signCtx->mdctx);
        if (NULL != signCtx) free (signCtx);
        return (jlong) NULL;
    }

    return (jlong) signCtx;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslRSANativeSignUpdate
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslRSANativeSignUpdate
  (JNIEnv *env, jclass this , jlong ctx, jbyteArray in)
{
    char *inbuf = NULL;
    size_t in_len = 0;
    int iErr = ERR_SUCCESS;

    SIGNCTX *signCtx = (SIGNCTX*) ctx;
    if (NULL == signCtx)
    {
        return ERR_FAILED;
    }

    do 
    {
        if (NULL == in)
        {
            iErr = ERR_FAILED;
            PRINT_ERROR ("invalid input");
            break;
        }

        if (!(inbuf = (char*)(*env)->GetByteArrayElements (env, in, 0))){
            PRINT_ERROR ("invalid input");
            iErr = ERR_FAILED;
            break;
        }

        in_len = (*env)->GetArrayLength (env, in);
        if (in_len == 0)
        {
            PRINT_ERROR ("invalid input");
            iErr = ERR_FAILED;
            break;
        }

        if (!EVP_DigestSignUpdate(&signCtx->mdctx, inbuf, in_len))
        {
            PRINT_ERROR ("EVP_SignUpdate failed");
            iErr = ERR_FAILED;
            break;
        }
    } while (0);

    if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte*)inbuf, JNI_ABORT);
    
    if (ERR_SUCCESS != iErr)
    {
        if (NULL != signCtx->pkey) EVP_PKEY_free (signCtx->pkey);
        EVP_MD_CTX_cleanup (&signCtx->mdctx);
        if (NULL != signCtx) free (signCtx);
    }

    return iErr;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslRSANativeSigndoFinal
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslRSANativeSigndoFinal
  (JNIEnv *env, jclass this, jlong ctx)
{
    jbyteArray ret = NULL;
    int iErr = ERR_SUCCESS;

    SIGNCTX *signCtx = (SIGNCTX*) ctx;
    if (NULL == signCtx)
    {
        return NULL;
    }

    do 
    {
        size_t signlen = EVP_PKEY_size (signCtx->pkey);
        unsigned char signbuf[signlen];
        memset (signbuf, 0, sizeof (signbuf));

        if (!EVP_DigestSignFinal(&signCtx->mdctx, signbuf, &signlen))
        {
            PRINT_ERROR ("EVP_DigestSignFinal failed");
            iErr = ERR_FAILED;
            break;
        }

        if (!(ret = (*env)->NewByteArray(env, signlen))) {
            PRINT_ERROR ("NewByteArray failed");
            iErr = ERR_FAILED;
            break;
        }

        (*env)->SetByteArrayRegion(env, ret, 0, signlen, (jbyte *)signbuf);
    } while (0);

    if (NULL != signCtx->pkey) EVP_PKEY_free (signCtx->pkey);
    EVP_MD_CTX_cleanup (&signCtx->mdctx);
    if (NULL != signCtx) free (signCtx);

    return ret;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslRSANativeVerifyInitContext
 * Signature: (Ljava/lang/String;[B)J
 * Note:      padding默认PKCS1,如有需要可以支持其他的
 */
JNIEXPORT jlong JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslRSANativeVerifyInitContext
  (JNIEnv *env , jclass this, jstring algor)
{
    SIGNCTX *signCtx = (SIGNCTX*) malloc (sizeof (SIGNCTX));
    if (NULL == signCtx)
    {
        return (jlong) NULL;
    }
    memset (signCtx, 0, sizeof (SIGNCTX));
    const char* alg = NULL;
	const unsigned char *p = NULL;
    int iErr = ERR_SUCCESS;
    OpenSSL_add_all_algorithms ();

    do
    {
        if (NULL == algor) 
        {
            iErr = ERR_FAILED;
            PRINT_ERROR ("invalid input");
            break;
        }

        if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
            iErr = ERR_FAILED;
            PRINT_ERROR("invalid alg");
            break;
        }

        if (!(signCtx->md = EVP_get_digestbyname(alg))) {
            iErr = ERR_FAILED;
            printf ("EVP_get_digestbyname failed, alg:%s\n", alg);
            break;
        }

        EVP_MD_CTX_init(&signCtx->mdctx);
    } while (0);

	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);

    if (ERR_SUCCESS != iErr)
    {
        if (NULL != signCtx->pkey) EVP_PKEY_free (signCtx->pkey);
        EVP_MD_CTX_cleanup (&signCtx->mdctx);
        if (NULL != signCtx) free (signCtx);
        return (jlong) NULL;
    }

    return (jlong) signCtx;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslRSANativeVerifyInitContext
 * Signature: (Ljava/lang/String;[B)J
 * Note:      padding默认PKCS1,如有需要可以支持其他的
 */
JNIEXPORT jint JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslRSANativeVerifyInit
  (JNIEnv *env , jclass this, jlong ctx, jbyteArray key)
{
    SIGNCTX *signCtx = (SIGNCTX*) ctx;
    if (NULL == signCtx)
    {
        return (jlong) NULL;
    }

	const unsigned char *p = NULL;
    unsigned char *keybuf = NULL;
	unsigned int keylen = 0;
    int iErr = ERR_SUCCESS;
    OpenSSL_add_all_algorithms ();

    do
    {
        if (NULL == key)
        {
            iErr = ERR_FAILED;
            PRINT_ERROR ("invalid input");
            break;
        }

        if (!(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))) {
            PRINT_ERROR ("invalid key");
            iErr = ERR_FAILED;
            break;
        }

        keylen = (size_t)(*env)->GetArrayLength(env, key);
        if (keylen == 0)
        {
            PRINT_ERROR ("invalid key length");
            iErr = ERR_FAILED;
            break;
        }

        unsigned char szDecBase64Buf[keylen];
        int tmplen = EVP_DecodeBlock(szDecBase64Buf, keybuf, keylen);
        p = szDecBase64Buf;
        if (!(signCtx->pkey = d2i_PUBKEY(&signCtx->pkey, &p, tmplen))){
            PRINT_ERROR ("d2i_AutoPrivateKey failed");
            iErr = ERR_FAILED;
            break;
        }

        if (!EVP_DigestVerifyInit(&signCtx->mdctx, &signCtx->pkctx, signCtx->md, NULL, signCtx->pkey))
        {
            iErr = ERR_FAILED;
            PRINT_ERROR("EVP_DigestSignInit failed.");
            break;
        }

        if (!EVP_PKEY_CTX_set_rsa_padding(signCtx->pkctx, RSA_PKCS1_PADDING)){
            PRINT_ERROR("EVP_PKEY_CTX_set_rsa_padding failed");
            iErr = ERR_FAILED;
            break;
        }

    } while (0);

    if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);

    if (ERR_SUCCESS != iErr)
    {
        if (NULL != signCtx->pkey) EVP_PKEY_free (signCtx->pkey);
        EVP_MD_CTX_cleanup (&signCtx->mdctx);
        if (NULL != signCtx) free (signCtx);
        return (jlong) NULL;
    }

    return (jlong) signCtx;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslRSANativeVerifyUpdate
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslRSANativeVerifyUpdate
  (JNIEnv *env, jclass this , jlong ctx, jbyteArray in)
{
    char *inbuf = NULL;
    size_t in_len = 0;
    int iErr = ERR_SUCCESS;

    SIGNCTX *signCtx = (SIGNCTX*) ctx;
    if (NULL == signCtx)
    {
        return ERR_FAILED;
    }

    do 
    {
        if (NULL == in)
        {
            iErr = ERR_FAILED;
            PRINT_ERROR ("invalid input");
            break;
        }

        if (!(inbuf = (char*)(*env)->GetByteArrayElements (env, in, 0))){
            PRINT_ERROR ("invalid input");
            iErr = ERR_FAILED;
            break;
        }

        in_len = (*env)->GetArrayLength (env, in);
        if (in_len == 0)
        {
            PRINT_ERROR ("invalid input");
            iErr = ERR_FAILED;
            break;
        }

        if (!EVP_DigestVerifyUpdate(&signCtx->mdctx, inbuf, in_len))
        {
            PRINT_ERROR ("EVP_DigestVerifyUpdate failed");
            iErr = ERR_FAILED;
            break;
        }
    } while (0);

    if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte*)inbuf, JNI_ABORT);
    
    if (ERR_SUCCESS != iErr)
    {
        if (NULL != signCtx->pkey) EVP_PKEY_free (signCtx->pkey);
        EVP_MD_CTX_cleanup (&signCtx->mdctx);
        if (NULL != signCtx) free (signCtx);
    }

    return iErr;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslRSANativeSigndoFinal
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslRSANativeVerifydoFinal
  (JNIEnv *env, jclass this, jlong ctx, jbyteArray sign)
{
    int iErr = ERR_SUCCESS;
    unsigned char* signbuf = NULL;
    size_t signlen = 0;

    SIGNCTX *signCtx = (SIGNCTX*) ctx;
    if (NULL == (void*) ctx)
    {
        return ERR_FAILED;
    }


    do 
    {
        if (NULL == sign)
        {
            iErr = ERR_FAILED;
            PRINT_ERROR ("invalid input");
            break;
        }

        if (!(signbuf = (unsigned char*)(*env)->GetByteArrayElements (env, sign, 0))){
            PRINT_ERROR ("invalid input");
            iErr = ERR_FAILED;
            break;
        }

        signlen = (*env)->GetArrayLength (env, sign);
        if (signlen == 0)
        {
            PRINT_ERROR ("invalid input");
            iErr = ERR_FAILED;
            break;
        }

        iErr = EVP_DigestVerifyFinal(&signCtx->mdctx, signbuf, signlen);
        if (ERR_SUCCESS != iErr)
        {
            break;
        }

    } while (0);

    if (signbuf) (*env)->ReleaseByteArrayElements(env, sign, (jbyte*)signbuf, JNI_ABORT);

    if (NULL != signCtx->pkey) EVP_PKEY_free (signCtx->pkey);
    EVP_MD_CTX_cleanup (&signCtx->mdctx);
    if (NULL != signCtx) free (signCtx);

    return (jint) iErr;
}

int get_sm2_public_key (EVP_PKEY *pstKey, char *pcPublicKey)
{
    unsigned char *pBuf          = NULL;
    int iBase64Len               = 0;
    unsigned char *pucPublicKey  = NULL;
    int ret                      = ERR_SUCCESS;
    BIO *bio                     = NULL;
    EC_KEY *ec                   = NULL;

    /* ------------create public key-------------------*/
    /* pkcs1 && DER format */
    do 
    {
        bio = BIO_new (BIO_s_mem());
        if (NULL == bio)
        {
            ret = ERR_FAILED;
            printf ("create mem bio failed.\n") ;
            break;
        }

        ec = EVP_PKEY_get1_EC_KEY (pstKey);
        if (NULL == ec)
        {
            ret = ERR_FAILED;
            printf ("get ec key failed.\n") ;
            break;
        }

        ret = i2d_EC_PUBKEY_bio (bio, ec);
        if (ERR_SUCCESS != ret)
        {
            printf ("i2d_EC_PUBKEY_bio, failed to create ec public key, err:%d.\n", ret);
            ret = ERR_FAILED;
            break;
        }

        /* get data from bio mem */
        BUF_MEM *ecptr = NULL;
        ret = BIO_get_mem_ptr(bio, &ecptr);
        if ((ERR_SUCCESS != ret) || (NULL == ecptr))
        {
            ret = ERR_FAILED;
            printf ("BIO_get_mem_ptr failed.\n") ;
            break;
        }

        pBuf = (unsigned char*) malloc (ecptr->length * 2);
        if (NULL == pBuf)
        {
            ret = ERR_FAILED;
            printf ("malloc failed\n");
            break;
        }
        memset (pBuf, 0, ecptr->length * 2);

        iBase64Len = EVP_EncodeBlock(pBuf, (unsigned char*)ecptr->data, ecptr->length);

        memcpy (pcPublicKey, pBuf, iBase64Len);
    } while (0);

    free (pBuf);
    EC_KEY_free(ec);
    BIO_free_all (bio);

    if (ERR_SUCCESS != ret)
    {
        printf ("get ec public key failed.\n");
        return ret;
    }

    return ERR_SUCCESS;
}

int get_sm2_private_key (EVP_PKEY *pstKey, char *pcPrivateKey)
{
    unsigned char *pBuf          = NULL;
    int iBase64Len               = 0;
    unsigned char *pucPublicKey  = NULL;
    int ret                      = ERR_SUCCESS;
    BIO *bio                     = NULL;

    /* ------------create private key-------------------*/
    /* pkcs8 && DER format */
    do 
    {
        bio = BIO_new (BIO_s_mem());
        if (NULL == bio)
        {
            ret = ERR_FAILED;
            printf ("create mem bio failed.\n") ;
            break;
        }

        ret = i2d_PKCS8PrivateKey_bio(bio, pstKey, NULL, NULL, 0, NULL, NULL);
        if (ERR_SUCCESS != ret)
        {
            printf ("failed write RSA private key into file, err:%d\n", ret) ;
            ret = ERR_FAILED;
            break;
        }

        /* get data from bio mem */
        BUF_MEM *bptr = NULL;
        ret = BIO_get_mem_ptr(bio, &bptr);
        if ((ERR_SUCCESS != ret) || (NULL == bptr))
        {
            ret = ERR_FAILED;
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
        memcpy (pcPrivateKey, pBuf, iBase64Len);

    } while (0);

    free (pBuf);
    BIO_free_all (bio);

    if (ERR_SUCCESS != ret)
    {
        printf ("get ec public key failed.\n");
        return ret;
    }

    return ERR_SUCCESS;
}

/*
 * Class:     org_apache_commons_crypto_cipher_OpenSslNative
 * Method:    generateSM2KeyPair
 * Signature: (I)Ljava/util/Map;
 */
JNIEXPORT jobject JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslNativegenerateSM2KeyPair
(JNIEnv *env, jclass jo)
{
    jclass class_map = (*env)->FindClass(env, "java/util/HashMap");
    jmethodID map_init = (*env)->GetMethodID(env, class_map, "<init>", "()V");
    jobject Map = (*env)->NewObject(env, class_map, map_init, "");
    jmethodID Map_put = (*env)->GetMethodID(env, class_map,
                                            "put",
                                            "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");

    int iErr                = ERR_SUCCESS;
	int curve_nid           = NID_sm2p256v1; /* 如果需要其他ECC，可以在这里设置, 比如NID_X9_62_prime256v1 */
	EVP_PKEY *pstKey        = NULL;
	EVP_PKEY_CTX *pkctx     = NULL;

    do 
    {
        if (!(pkctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
            fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
            iErr = ERR_FAILED;
            break;
        }

        if (!EVP_PKEY_keygen_init(pkctx)) {
            fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
            iErr = ERR_FAILED;
            break;
        }

        if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkctx, curve_nid)) {
            fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
            iErr = ERR_FAILED;
            break;
        }

        if (!EVP_PKEY_keygen(pkctx, &pstKey)) {
            fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
            iErr = ERR_FAILED;
            break;
        }

#if 0
        printf("SM2-ECC Key size: %d bit\n", EVP_PKEY_bits(pstKey));
        printf("SM2-ECC Key type: %s\n", OBJ_nid2sn(curve_nid));
#endif
#if 0
        /* write out PEM format keys */
        BIO *outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
        if(!PEM_write_bio_PUBKEY(outbio, pstKey))
            BIO_printf(outbio, "Error writing public key data in PEM format");

        if(!PEM_write_bio_PrivateKey(outbio, pstKey, NULL, NULL, 0, 0, NULL))
            BIO_printf(outbio, "Error writing private key data in PEM format");
#endif

        char szPublicKey[1024] = {0};
        get_sm2_public_key (pstKey, szPublicKey);
        (*env)->CallObjectMethod(env, Map, Map_put,
                (*env)->NewStringUTF(env,"pk"),
                (*env)->NewStringUTF(env, szPublicKey));

        char szPrivateKey[1024] = {0};
        get_sm2_private_key (pstKey, szPrivateKey);
        (*env)->CallObjectMethod(env, Map, Map_put,
                (*env)->NewStringUTF(env,"pv"),
                (*env)->NewStringUTF(env, szPrivateKey));

    } while (0);

    if (NULL != pstKey) 
    {
        EVP_PKEY_free(pstKey);
    }
    if (NULL != pkctx)
    {
        EVP_PKEY_CTX_free(pkctx);
    }

    if (ERR_SUCCESS != iErr)
    {
        (*env)->CallObjectMethod(env, Map, Map_put,
                                 (*env)->NewStringUTF(env,"pk"),
                                 (*env)->NewStringUTF(env, "invalid pk"));
        (*env)->CallObjectMethod(env, Map, Map_put,
                                (*env)->NewStringUTF(env,"pv"),
                                (*env)->NewStringUTF(env, "invalid pv"));
    }

    return Map;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslNativeSM2CryptInitContext
 * Signature: (I[B)J
 * Note:      mode, padding实际没使用到
 */
JNIEXPORT jlong JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslNativeSM2CryptInitContext
  (JNIEnv *env, jclass this, jint mode,  jint padding)
{
    int iErr = ERR_SUCCESS;

    (void) mode;
    (void) padding;

    SM2CTX *sm2Context = NULL;

    do 
    {
        sm2Context = (SM2CTX*) malloc (sizeof (SM2CTX));
        if (NULL == sm2Context)
        {
            PRINT_ERROR("malloc failed");
            iErr = ERR_FAILED;
            break;
        }

    } while (0);

    if (ERR_SUCCESS != iErr)
    {
        free (sm2Context);
        sm2Context = NULL;
    }

	return (jlong) sm2Context;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslNativeSM2CryptInit
 * Signature: (I[B)J
 */
JNIEXPORT jint JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslNativeSM2CryptInit
  (JNIEnv *env, jclass this, jlong ctx, jint mode,  jbyteArray key)
{
	unsigned char *keybuf = NULL;
	size_t keylen = 0;
	const unsigned char *p = NULL;
	EVP_PKEY *pkey = NULL;
    int iErr = ERR_SUCCESS;

    SM2CTX *sm2Context = (SM2CTX*) ctx;
    if (NULL == sm2Context)
    {
        return ERR_FAILED;
    }

    do 
    {
        sm2Context->cryptmode = mode;

        if (NULL == key)
        {
            PRINT_ERROR ("invalid input ");
            iErr = ERR_FAILED;
            break;
        }

        if (!(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))) {
            PRINT_ERROR ("invalid key");
            iErr = ERR_FAILED;
            break;
        }

        keylen = (size_t)(*env)->GetArrayLength(env, key);
        if (keylen == 0)
        {
            PRINT_ERROR ("invalid key length");
            iErr = ERR_FAILED;
            break;
        }

        unsigned char szDecBase64Buf[keylen];
        int tmplen = EVP_DecodeBlock(szDecBase64Buf, keybuf, keylen);

        p = szDecBase64Buf;
        if (ENCRYPT == sm2Context->cryptmode)
        {
            if (!(pkey = d2i_PUBKEY(&pkey, &p, tmplen))) {
                PRINT_ERROR ("d2i_PUBKEY failed");
                iErr = ERR_FAILED;
                break;
            }
        }
        else
        {
            if (!(pkey = d2i_AutoPrivateKey(NULL, &p, tmplen))){
                PRINT_ERROR ("d2i_AutoPrivateKey failed");
                iErr = ERR_FAILED;
                break;
            }
        }

        if (!(sm2Context->pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
            PRINT_ERROR("EVP_PKEY_CTX_new failed");
            iErr = ERR_FAILED;
            break;
        }

        if (ENCRYPT == sm2Context->cryptmode)
        {
            if (!EVP_PKEY_encrypt_init(sm2Context->pkctx)) 
            {
                PRINT_ERROR("EVP_PKEY_encrypt_init failed");
                iErr = ERR_FAILED;
                break;
            }
        }
        else
        {
            if (!EVP_PKEY_decrypt_init(sm2Context->pkctx))
            {
                PRINT_ERROR("EVP_PKEY_decrypt_init failed");
                iErr = ERR_FAILED;
                break;
            }
        }

    } while (0);

    if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
    EVP_PKEY_free(pkey);

    if (ERR_SUCCESS != iErr)
    {
        if (NULL != sm2Context->pkctx) EVP_PKEY_CTX_free(sm2Context->pkctx);
        free(sm2Context);
    }

	return iErr;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslNativeSM2CryptUpdate
 * Signature: (JI[B)[B
 */
static JNIEXPORT jbyteArray JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslNativeSM2CryptUpdate
  (JNIEnv *env, jclass this, jlong ctx, jbyteArray in)
{
	jbyteArray ret = NULL;
	unsigned char *inbuf = NULL;
	unsigned char *outbuf = NULL;
	size_t inlen, outlen;
	EVP_PKEY *pkey = NULL;
    int iErr = ERR_SUCCESS;

    SM2CTX *sm2Context = (SM2CTX*) ctx;
    if (NULL == sm2Context)
    {
        return ret;
    }

    do 
    {
        if (NULL == in)
        {
            PRINT_ERROR ("invalid input ");
            iErr = ERR_FAILED;
            break;
        }

        if (!(inbuf = (unsigned char *)(*env)->GetByteArrayElements(env, in, 0))) {
            PRINT_ERROR ("invalid input ");
            iErr = ERR_FAILED;
            break;
        }

        inlen = (size_t)(*env)->GetArrayLength(env, in);
        if (inlen <= 0) {
            PRINT_ERROR ("invalid in length");
            iErr = ERR_FAILED;
            break;
        }

        /* we can not get ciphertext length from plaintext
         * so malloc the max buffer
         */
        outlen = inlen + 2048;
        if (!(outbuf = malloc(outlen))) {
            PRINT_ERROR("malloc failed");
            iErr = ERR_FAILED;
            break;
        }

        if (ENCRYPT == sm2Context->cryptmode)
        {
            if (!EVP_PKEY_encrypt(sm2Context->pkctx, outbuf, &outlen, inbuf, inlen)) {
                PRINT_ERROR("EVP_PKEY_encrypt failed");
                iErr = ERR_FAILED;
                break;
            }
        }
        else
        {
            if (!EVP_PKEY_decrypt(sm2Context->pkctx, outbuf, &outlen, inbuf, inlen)) {
                PRINT_ERROR("EVP_PKEY_decrypt failed");
                iErr = ERR_FAILED;
                break;
            }
        }

        if (!(ret = (*env)->NewByteArray(env, outlen))) {
            PRINT_ERROR("NewByteArray failed");
            iErr = ERR_FAILED;
            break;
        }

        (*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);
    } while (0);

    if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
    if (outbuf) free(outbuf);

    if (ERR_SUCCESS != iErr)
    {
        if (NULL != sm2Context->pkctx) EVP_PKEY_CTX_free(sm2Context->pkctx);
        free(sm2Context);
    }

	return ret;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslNativeSM2CryptdoFinal
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslNativeSM2CryptdoFinal
  (JNIEnv *env, jclass this, jlong ctx, jbyteArray in)
{
	jbyteArray ret = NULL;

    SM2CTX *sm2Context = (SM2CTX*) ctx;
    if (NULL == sm2Context)
    {
        return ret;
    }

    ret = Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslNativeSM2CryptUpdate (env, this, (jlong) sm2Context, in);
    if (NULL == ret)
    {
        return ret;
    }

    if (NULL != sm2Context->pkctx) EVP_PKEY_CTX_free(sm2Context->pkctx);
    free(sm2Context);

    return ret;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslNativeSM2SignInitContext
 * Signature: (Ljava/lang/String;[B)J
 */
JNIEXPORT jlong JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslNativeSM2SignInitContext
  (JNIEnv *env , jclass this, jstring algor)
{
    SIGNCTX *signCtx = (SIGNCTX*) malloc (sizeof (SIGNCTX));
    if (NULL == signCtx)
    {
        return (jlong) NULL;
    }
    memset (signCtx, 0, sizeof (SIGNCTX));

    const char* alg = NULL;
	const EVP_MD *md = NULL;
    int iErr = ERR_SUCCESS;
    OpenSSL_add_all_algorithms ();

    do
    {
        if (NULL == algor)
        {
            iErr = ERR_FAILED;
            PRINT_ERROR ("invalid input");
            break;
        }

        if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
            iErr = ERR_FAILED;
            PRINT_ERROR("invalid alg");
            break;
        }

        if (!(signCtx->md = EVP_get_digestbyname(alg))) {
            iErr = ERR_FAILED;
            printf ("EVP_get_digestbyname failed, alg:%s\n", alg);
            break;
        }

        EVP_MD_CTX_init(&signCtx->mdctx);
    } while (0);

	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);

    if (ERR_SUCCESS != iErr)
    {
        if (NULL != signCtx) free (signCtx);
        return (jlong) NULL;
    }

    return (jlong) signCtx;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslNativeSM2SignInitContext
 * Signature: (Ljava/lang/String;[B)J
 */
JNIEXPORT jint JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslNativeSM2SignInit
  (JNIEnv *env , jclass this, jlong ctx, jbyteArray key)
{
	const unsigned char *p = NULL;
    unsigned char *keybuf = NULL;
	unsigned int keylen = 0;
	const EVP_MD *md = NULL;
    int iErr = ERR_SUCCESS;
    OpenSSL_add_all_algorithms ();

    SIGNCTX *signCtx = (SIGNCTX*) ctx;
    if (NULL == signCtx)
    {
        return ERR_FAILED;
    }

    do
    {
        if (NULL == key)
        {
            iErr = ERR_FAILED;
            PRINT_ERROR ("invalid input");
            break;
        }

        if (!(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))) {
            PRINT_ERROR ("invalid key");
            iErr = ERR_FAILED;
            break;
        }

        keylen = (size_t)(*env)->GetArrayLength(env, key);
        if (keylen == 0)
        {
            PRINT_ERROR ("invalid key length");
            iErr = ERR_FAILED;
            break;
        }

        unsigned char szDecBase64Buf[keylen];
        int tmplen = EVP_DecodeBlock(szDecBase64Buf, keybuf, keylen);
        p = szDecBase64Buf;
        if (!(signCtx->pkey = d2i_AutoPrivateKey(NULL, &p, tmplen))){
            PRINT_ERROR ("d2i_AutoPrivateKey failed");
            iErr = ERR_FAILED;
            break;
        }

        if (!EVP_DigestSignInit(&signCtx->mdctx, &signCtx->pkctx, signCtx->md, NULL, signCtx->pkey))
        {
            printf ("EVP_DigestSignInit failed, %s\n", LOCKET_ERR_GetString ());
            iErr = ERR_FAILED;
            PRINT_ERROR("EVP_DigestSignInit failed.");
            break;
        }
    } while (0);

    if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);

    if (ERR_SUCCESS != iErr)
    {
        if (NULL != signCtx->pkey) EVP_PKEY_free (signCtx->pkey);
        EVP_MD_CTX_cleanup (&signCtx->mdctx);
        if (NULL != signCtx) free (signCtx);
    }

    return iErr;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslNativeSM2SignUpdate
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslNativeSM2SignUpdate
  (JNIEnv *env, jclass this , jlong ctx, jbyteArray in)
{
    char *inbuf = NULL;
    size_t in_len = 0;
    int iErr = ERR_SUCCESS;

    SIGNCTX *signCtx = (SIGNCTX*) ctx;
    if (NULL == signCtx)
    {
        return ERR_FAILED;
    }

    do 
    {
        if (NULL == in)
        {
            iErr = ERR_FAILED;
            PRINT_ERROR ("invalid input");
            break;
        }

        if (!(inbuf = (char*)(*env)->GetByteArrayElements (env, in, 0))){
            PRINT_ERROR ("invalid input");
            iErr = ERR_FAILED;
            break;
        }

        in_len = (*env)->GetArrayLength (env, in);
        if (in_len == 0)
        {
            PRINT_ERROR ("invalid input");
            iErr = ERR_FAILED;
            break;
        }

        if (!EVP_DigestSignUpdate(&signCtx->mdctx, inbuf, in_len))
        {
            PRINT_ERROR ("EVP_SignUpdate failed");
            iErr = ERR_FAILED;
            break;
        }
    } while (0);

    if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte*)inbuf, JNI_ABORT);
    
    if (ERR_SUCCESS != iErr)
    {
        if (NULL != signCtx->pkey) EVP_PKEY_free (signCtx->pkey);
        EVP_MD_CTX_cleanup (&signCtx->mdctx);
        if (NULL != signCtx) free (signCtx);
    }

    return iErr;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslNativeSM2SigndoFinal
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslNativeSM2SigndoFinal
  (JNIEnv *env, jclass this, jlong ctx)
{
    jbyteArray ret = NULL;
    int iErr = ERR_SUCCESS;

    SIGNCTX *signCtx = (SIGNCTX*) ctx;
    if (NULL == signCtx)
    {
        return ret;
    }

    do 
    {
        size_t signlen = EVP_PKEY_size (signCtx->pkey);
        unsigned char signbuf[signlen];
        memset (signbuf, 0, sizeof (signbuf));

        if (!EVP_DigestSignFinal(&signCtx->mdctx, signbuf, &signlen))
        {
            PRINT_ERROR ("EVP_DigestSignFinal failed");
            iErr = ERR_FAILED;
            break;
        }

        if (!(ret = (*env)->NewByteArray(env, signlen))) {
            PRINT_ERROR ("NewByteArray failed");
            iErr = ERR_FAILED;
            break;
        }

        (*env)->SetByteArrayRegion(env, ret, 0, signlen, (jbyte *)signbuf);
    } while (0);

    if (NULL != signCtx->pkey) EVP_PKEY_free (signCtx->pkey);
    EVP_MD_CTX_cleanup (&signCtx->mdctx);
    if (NULL != signCtx) free (signCtx);

    return ret;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslNativeSM2VerifyInitContext
 * Signature: (Ljava/lang/String;[B)J
 */
JNIEXPORT jlong JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslNativeSM2VerifyInitContext
  (JNIEnv *env , jclass this, jstring algor)
{
    SIGNCTX *signCtx = (SIGNCTX*) malloc (sizeof (SIGNCTX));
    if (NULL == signCtx)
    {
        return (jlong) NULL;
    }
    memset (signCtx, 0, sizeof (SIGNCTX));

    const char* alg = NULL;
	const unsigned char *p = NULL;
    int iErr = ERR_SUCCESS;
    OpenSSL_add_all_algorithms ();

    do
    {
        if (NULL == algor)
        {
            iErr = ERR_FAILED;
            PRINT_ERROR ("invalid input");
            break;
        }

        if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
            iErr = ERR_FAILED;
            PRINT_ERROR("invalid alg");
            break;
        }

        if (!(signCtx->md = EVP_get_digestbyname(alg))) {
            iErr = ERR_FAILED;
            printf ("EVP_get_digestbyname failed, alg:%s\n", alg);
            break;
        }

        EVP_MD_CTX_init(&signCtx->mdctx);

    } while (0);

	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);

    if (ERR_SUCCESS != iErr)
    {
        if (NULL != signCtx) free (signCtx);
        return (jlong) NULL;
    }

    return (jlong) signCtx;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslNativeSM2VerifyInit
 * Signature: (Ljava/lang/String;[B)J
 */
JNIEXPORT jint JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslNativeSM2VerifyInit
  (JNIEnv *env , jclass this, jlong ctx, jbyteArray key)
{
	const unsigned char *p = NULL;
    unsigned char *keybuf = NULL;
	unsigned int keylen = 0;
	const EVP_MD *md = NULL;
    int iErr = ERR_SUCCESS;
    OpenSSL_add_all_algorithms ();

    SIGNCTX *signCtx = (SIGNCTX*) ctx;
    if (NULL == signCtx)
    {
        return ERR_FAILED;
    }

    do
    {
        if (NULL == key)
        {
            iErr = ERR_FAILED;
            PRINT_ERROR ("invalid input");
            break;
        }

        if (!(keybuf = (unsigned char *)(*env)->GetByteArrayElements(env, key, 0))) {
            PRINT_ERROR ("invalid key");
            iErr = ERR_FAILED;
            break;
        }

        keylen = (size_t)(*env)->GetArrayLength(env, key);
        if (keylen == 0)
        {
            PRINT_ERROR ("invalid key length");
            iErr = ERR_FAILED;
            break;
        }

        unsigned char szDecBase64Buf[keylen];
        int tmplen = EVP_DecodeBlock(szDecBase64Buf, keybuf, keylen);
        p = szDecBase64Buf;
        if (!(signCtx->pkey = d2i_PUBKEY(&signCtx->pkey, &p, tmplen))){
            PRINT_ERROR ("d2i_AutoPrivateKey failed");
            iErr = ERR_FAILED;
            break;
        }

        if (!EVP_DigestVerifyInit(&signCtx->mdctx, &signCtx->pkctx, signCtx->md, NULL, signCtx->pkey))
        {
            iErr = ERR_FAILED;
            PRINT_ERROR("EVP_DigestSignInit failed.");
            break;
        }

    } while (0);

    if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);

    if (ERR_SUCCESS != iErr)
    {
        if (NULL != signCtx->pkey) EVP_PKEY_free (signCtx->pkey);
        EVP_MD_CTX_cleanup (&signCtx->mdctx);
        if (NULL != signCtx) free (signCtx);
    }

    return iErr;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslNativeSM2VerifyUpdate
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslNativeSM2VerifyUpdate
  (JNIEnv *env, jclass this , jlong ctx, jbyteArray in)
{
    char *inbuf = NULL;
    size_t in_len = 0;
    int iErr = ERR_SUCCESS;

    SIGNCTX *signCtx = (SIGNCTX*) ctx;
    if (NULL == signCtx)
    {
        return ERR_FAILED;
    }

    do 
    {
        if (NULL == in)
        {
            iErr = ERR_FAILED;
            PRINT_ERROR ("invalid input");
            break;
        }

        if (!(inbuf = (char*)(*env)->GetByteArrayElements (env, in, 0))){
            PRINT_ERROR ("invalid input");
            iErr = ERR_FAILED;
            break;
        }

        in_len = (*env)->GetArrayLength (env, in);
        if (in_len == 0)
        {
            PRINT_ERROR ("invalid input");
            iErr = ERR_FAILED;
            break;
        }

        if (!EVP_DigestVerifyUpdate(&signCtx->mdctx, inbuf, in_len))
        {
            PRINT_ERROR ("EVP_DigestVerifyUpdate failed");
            iErr = ERR_FAILED;
            break;
        }
    } while (0);

    if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte*)inbuf, JNI_ABORT);
    
    if (ERR_SUCCESS != iErr)
    {
        if (NULL != signCtx->pkey) EVP_PKEY_free (signCtx->pkey);
        EVP_MD_CTX_cleanup (&signCtx->mdctx);
        if (NULL != signCtx) free (signCtx);
    }

    return iErr;
}

/*
 * Class:     com_zenzet_cipher_crypto_Mycrypt
 * Method:    OpenSslNativeSM2VerifydoFinal
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_com_zenzet_cipher_crypto_Mycrypt_OpenSslNativeSM2VerifydoFinal
  (JNIEnv *env, jclass this, jlong ctx, jbyteArray sign)
{
    int iErr = ERR_SUCCESS;
    unsigned char* signbuf = NULL;
    size_t signlen = 0;

    SIGNCTX *signCtx = (SIGNCTX*) ctx;
    if (NULL == signCtx)
    {
        return ERR_FAILED;
    }

    do 
    {
        if (NULL == sign)
        {
            iErr = ERR_FAILED;
            PRINT_ERROR ("invalid input");
            break;
        }

        if (!(signbuf = (unsigned char*)(*env)->GetByteArrayElements (env, sign, 0))){
            PRINT_ERROR ("invalid input");
            iErr = ERR_FAILED;
            break;
        }

        signlen = (*env)->GetArrayLength (env, sign);
        if (signlen == 0)
        {
            PRINT_ERROR ("invalid input");
            iErr = ERR_FAILED;
            break;
        }

        iErr = EVP_DigestVerifyFinal(&signCtx->mdctx, signbuf, signlen);
        if (ERR_SUCCESS != iErr)
        {
            break;
        }

    } while (0);

    if (signbuf) (*env)->ReleaseByteArrayElements(env, sign, (jbyte*)signbuf, JNI_ABORT);

    if (NULL != signCtx->pkey) EVP_PKEY_free (signCtx->pkey);
    EVP_MD_CTX_cleanup (&signCtx->mdctx);
    if (NULL != signCtx) free (signCtx);

    return (jint) iErr;
}
