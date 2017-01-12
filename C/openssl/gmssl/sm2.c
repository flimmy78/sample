/* system header */
#include <string.h>

/* 3rd project header */
#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/err.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/bn.h" // this is for the BN_new

#define ERR_SUCCESS     1
#define ERR_FAILED      2
#define PRINT_ERROR(msg)  fprintf(stderr, "error:%s %s %d\n", msg, __FILE__, __LINE__)

char* LOCKET_ERR_GetString (void)
{
    int static iInit = 0;

    /* 加载错误信息 */
    if (!iInit)
    {
        ERR_load_ERR_strings();
        ERR_load_crypto_strings();
        iInit = 1;
    }

    return ERR_error_string(ERR_get_error(),NULL);
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

    return 0;
}

int get_sm2_private_key (EVP_PKEY *pstKey, char *pcPrivateKey)
{
    unsigned char *pBuf          = NULL;
    int iBase64Len               = 0;
    unsigned char *pucPublicKey  = NULL;
    int ret                      = ERR_SUCCESS;
    BIO *bio                     = NULL;

    do 
    {
        /* ------------create private key-------------------*/
        /* pkcs8 && DER format */
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
#if 0
        EVP_PKEY_print_private(out, pstKey, 4, NULL);
        BIO_printf(out, "\n");
#endif
    } while (0);

    free (pBuf);
    BIO_free_all (bio);

    if (ERR_SUCCESS != ret)
    {
        printf ("get ec public key failed.\n");
        return ret;
    }

    return 0;
}

EVP_PKEY *gen_sm2_key_pair(char szPublicKey[], char szPrivateKey[])
{
    //NID_X9_62_prime256v1 标准ECC的椭圆曲线
    //NID_sm2p256v1     SM2椭圆曲线
	int curve_nid = NID_sm2p256v1;
	EVP_PKEY *pstKey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;

	if (!(pkctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_PKEY_keygen_init(pkctx)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkctx, curve_nid)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_PKEY_keygen(pkctx, &pstKey)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

    printf("ECC Key size: %d bit\n", EVP_PKEY_bits(pstKey));
    printf("ECC Key type: %s\n", OBJ_nid2sn(curve_nid));

    get_sm2_public_key (pstKey, szPublicKey);
    printf ("SM2 Public Key:\n%s\n", szPublicKey);

    get_sm2_private_key (pstKey, szPrivateKey);
    printf ("SM2 Private Key:\n%s\n", szPrivateKey);


#if 0
    /* write out PEM format keys */
    BIO *outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
    if(!PEM_write_bio_PUBKEY(outbio, pstKey))
        BIO_printf(outbio, "Error writing public key data in PEM format");

    if(!PEM_write_bio_PrivateKey(outbio, pstKey, NULL, NULL, 0, 0, NULL))
        BIO_printf(outbio, "Error writing private key data in PEM format");
#endif

end:
	if (pstKey) {
		EVP_PKEY_free(pstKey);
		pstKey = NULL;
	}
	EVP_PKEY_CTX_free(pkctx);
	return pstKey;
}

int publickey_encrypt (unsigned char szPublicKey[], char *in, int inlen, char* out, int *poutlen)
{
	size_t keylen, outlen;
	const unsigned char *p = NULL;
    unsigned char *outbuf = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;
    int iErr = ERR_SUCCESS;

    do 
    {
#if 1
        keylen = strlen((char*) szPublicKey);
        unsigned char szBuffer[keylen];
        keylen = EVP_DecodeBlock(szBuffer, szPublicKey, strlen((char*)szPublicKey));
        p = szBuffer;
#endif

#if 1
        pkey = d2i_PUBKEY (&pkey, &p, keylen);
        if (NULL == pkey)
        {
            PRINT_ERROR ("d2i_PUBKEY failed");
            printf ("openssl err:%s\n", LOCKET_ERR_GetString ());
            iErr = ERR_FAILED;
            break;
        }
#endif
        /* we can not get ciphertext length from plaintext
         * so malloc the max buffer
         */
        outlen = inlen + 2048;
        if (!(outbuf = malloc(outlen))) {
            PRINT_ERROR("malloc failed");
            iErr = ERR_FAILED;
            break;
        }

        if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
            PRINT_ERROR("EVP_PKEY_CTX_new failed");
            printf ("openssl err:%s\n", LOCKET_ERR_GetString ());
            iErr = ERR_FAILED;
            break;
        }

        if (!EVP_PKEY_encrypt_init(pkctx)) {
            PRINT_ERROR("EVP_PKEY_encrypt_init failed");
            iErr = ERR_FAILED;
            break;
        }

#if 0
        if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
            if (!EVP_PKEY_CTX_ctrl_str(pkctx, "ec_encrypt_algor", alg)) {
                PRINT_ERROR("EVP_PKEY_CTX_ctrl_str failed");
                iErr = ERR_FAILED;
                break;
            }
        }
#endif
#if 1
        if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA) {
            printf ("*******rsa\n");
            if (!EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PADDING)){
                PRINT_ERROR("EVP_PKEY_CTX_set_rsa_padding failed");
                iErr = ERR_FAILED;
                break;
            }
        }
#endif

        if (!EVP_PKEY_encrypt(pkctx, outbuf, &outlen, (unsigned char*)in, inlen)) {
            PRINT_ERROR("EVP_PKEY_encrypt failed");
            iErr = ERR_FAILED;
            break;
        }

        *poutlen = outlen;
        memcpy (out, outbuf, outlen);
    } while (0);

    if (ERR_SUCCESS == iErr)
    {
        printf ("encrypt len:%lu\n", outlen);
        printf ("encrypt buffer:");
        for (int i = 0; i < outlen; i++)
        {
            printf ("%02x", outbuf[i]);
        }
        printf ("\n");
    }

	free (outbuf);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pkctx);

	return iErr;
}

int privatekey_decrypt (unsigned char szPrivateKey[], char *in, int inlen)
{
	size_t keylen, outlen;
	const unsigned char *p = NULL;
    unsigned char *outbuf = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;
    int iErr = ERR_SUCCESS;

    do 
    {
        keylen = strlen((char*) szPrivateKey);
        unsigned char szBuffer[keylen];
        keylen = EVP_DecodeBlock(szBuffer, szPrivateKey, strlen((char*)szPrivateKey));

        p = szBuffer;
        pkey = d2i_AutoPrivateKey(NULL, &p, keylen);
        if (NULL == pkey)
        {
            PRINT_ERROR ("d2i_AutoPrivateKey failed");
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
        memset (outbuf, 0, outlen);

        if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
            PRINT_ERROR("EVP_PKEY_CTX_new failed");
            iErr = ERR_FAILED;
            break;
        }

        if (!EVP_PKEY_decrypt_init(pkctx)) {
            PRINT_ERROR("EVP_PKEY_encrypt_init failed");
            iErr = ERR_FAILED;
            break;
        }
        if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA) {
            printf ("*******rsa\n");
            if (!EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PADDING)){
                PRINT_ERROR("EVP_PKEY_CTX_set_rsa_padding failed");
                iErr = ERR_FAILED;
                break;
            }
        }

#if 0
        if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
            printf ("xxx\n");
            if (!EVP_PKEY_CTX_ctrl_str(pkctx, "ec_decrypt_algor", alg)) {
                PRINT_ERROR("EVP_PKEY_CTX_ctrl_str failed");
                iErr = ERR_FAILED;
                break;
            }
        }
#endif

        if (!EVP_PKEY_decrypt(pkctx, outbuf, &outlen, (unsigned char*)in, inlen)) {
            PRINT_ERROR("EVP_PKEY_decrypt failed");
            iErr = ERR_FAILED;
            break;
        }
    } while (0);

    if (ERR_SUCCESS == iErr)
    {
        printf ("decrypt outlen:%lu\n", outlen);
        printf ("decrypt buffer:%s\n", outbuf);
    }

	free (outbuf);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pkctx);

	return iErr;
}

int sm2_crypt (char szPublicKey[], char szPrivateKey[])
{
    int ret = ERR_SUCCESS;
    char *in = "hello,world";
    int inlen = strlen(in);
    char out[8096] = {0};
    int outlen = 0;
    ret = publickey_encrypt ((unsigned char*)szPublicKey, in, inlen, out, &outlen);
    if (ERR_SUCCESS != ret)
    {
        printf ("pubic key encrypt failed\n");
        return ret;
    }

    in = out;
    inlen = outlen;
    ret = privatekey_decrypt ((unsigned char*) szPrivateKey, in, inlen);
    if (ERR_SUCCESS != ret)
    {
        printf ("private key decrypt failed\n");
        return ret;
    }

    return ERR_SUCCESS;
}

int gen_rsa_key_pair (char szPublicKey[], char szPrivateKey[], int keylen)
{
   	RSA *rsa            = NULL;
	int modulelen       = keylen;
	int ret             = ERR_SUCCESS;
	BIGNUM *bn          = NULL;
	unsigned long e     = RSA_F4;
    EVP_PKEY *pstKey    = NULL;
    unsigned char *pBuf = NULL;
    int iBase64Len      = 0;
    BIO *bioPtr         = NULL;
    unsigned char *pucPublicKey  = NULL;

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

        int iPubKeyLen = i2d_RSA_PUBKEY(rsa, &pp); //DER, i2d_RSAPublicKey????DER?
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

        memcpy (szPublicKey, pBuf, iBase64Len);
        printf ("RSA Public Key:\n%s\n", szPublicKey);

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
        memcpy (szPrivateKey, pBuf, iBase64Len);
        printf ("RSA Private Key:\n%s\n", szPrivateKey);

    } while (0);

    free(pucPublicKey);
    free (pBuf);
    EVP_PKEY_free(pstKey);
    BIO_free_all (bioPtr);

    return ret;	
}

int rsa_crypt (char szPublicKey[], char szPrivateKey[])
{
    return sm2_crypt (szPublicKey, szPrivateKey);
}

int asymmetric_sign (char *szPrivateKey, char *in, int inlen, char *signout, int *signlen)
{
    /* 改接口内部的实现，摘要算法不可选, 如果要选用其他摘要算法需要使用EVP_DigestSignInit这个系列的接口 */
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;
    size_t outlen = 0;
    const unsigned char *p = (unsigned char*)in;
    unsigned char *outbuf = NULL;
    int keylen = 0;
    int iErr = ERR_SUCCESS;

    do 
    {
        keylen = strlen((char*) szPrivateKey);
        unsigned char szBuffer[keylen];
        keylen = EVP_DecodeBlock(szBuffer, (unsigned char*)szPrivateKey, strlen((char*)szPrivateKey));
        p = szBuffer;

        pkey = d2i_AutoPrivateKey (NULL, &p, keylen);
        if (NULL == pkey)
        {
            PRINT_ERROR ("d2i_AutoPrivateKey failed");
            iErr = ERR_FAILED;
            break;
        }

        outlen = EVP_PKEY_size (pkey);
        if (0 == outlen)
        {
            PRINT_ERROR ("EVP_PKEY_size failed");
            iErr = ERR_FAILED;
            break;
        }
        outbuf = (unsigned char*) malloc (outlen);
        if (NULL == outbuf)
        {
            PRINT_ERROR ("malloc failed");
            iErr = ERR_FAILED;
            break;
        }

        pkctx = EVP_PKEY_CTX_new (pkey, NULL);
        if (NULL == pkctx)
        {
            PRINT_ERROR ("EVP_PKEY_CTX_new failed");
            iErr = ERR_FAILED;
            break;
        }

        iErr = EVP_PKEY_sign_init(pkctx);
        if (ERR_SUCCESS != iErr)
        {
            PRINT_ERROR ("EVP_PKEY_sign_init failed");
            iErr = ERR_FAILED;
            break;
        }

        iErr = EVP_PKEY_sign(pkctx, outbuf, &outlen, (unsigned char*)in, inlen);
        if (ERR_SUCCESS != iErr)
        {
            PRINT_ERROR ("EVP_PKEY_sign failed");
            iErr = ERR_FAILED;
            break;
        }
        printf ("Sign outlen:%lu\n", outlen);

        printf("Sign buffer:\n");
        int i = 0;
        for (i = 0; i< outlen; i++)
        {
            printf ("%02x", outbuf[i]);
        }
        printf ("\n");
        memcpy (signout, outbuf, outlen);
        *signlen = outlen;

    } while (0);


    free (outbuf);
    EVP_PKEY_free (pkey);
    EVP_PKEY_CTX_free (pkctx);
    
    return iErr;
}

int asymmetric_verify (char *szPublicKey, char *signin, int signlen, char *in, int inlen)
{
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;
    const unsigned char *p = (unsigned char*)in;
    int keylen = 0;
    int iErr = ERR_SUCCESS;

    do 
    {
        keylen = strlen((char*) szPublicKey);
        unsigned char szBuffer[keylen];
        keylen = EVP_DecodeBlock(szBuffer, (unsigned char*)szPublicKey, strlen((char*)szPublicKey));
        p = szBuffer;

        pkey = d2i_PUBKEY (&pkey, &p, keylen);
        if (NULL == pkey)
        {
            PRINT_ERROR ("d2i_PUBKEY failed");
            iErr = ERR_FAILED;
            break;
        }

        pkctx = EVP_PKEY_CTX_new (pkey, NULL);
        if (NULL == pkctx)
        {
            PRINT_ERROR ("EVP_PKEY_CTX_new failed");
            iErr = ERR_FAILED;
            break;
        }

        iErr = EVP_PKEY_verify_init(pkctx);
        if (ERR_SUCCESS != iErr)
        {
            PRINT_ERROR ("EVP_PKEY_veryfi_init failed");
            iErr = ERR_FAILED;
            break;
        }

        iErr = EVP_PKEY_verify(pkctx, (unsigned char*)signin, signlen, (unsigned char*)in, inlen);
        if (ERR_SUCCESS != iErr)
        {
            PRINT_ERROR ("EVP_PKEY_veryfi failed");
            iErr = ERR_FAILED;
            break;
        }
        printf ("Sign OK\n");
    } while (0);

    if (ERR_SUCCESS != iErr)
    {
        printf ("Sign failed\n");
    }


    EVP_PKEY_free (pkey);
    EVP_PKEY_CTX_free (pkctx);
    
    return iErr;
}

void rsa_test_large_file (char szPublicKey[], char szPrivateKey[])
{
	size_t keylen, outlen;
	const unsigned char *p = NULL;
    unsigned char *outbuf = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;
    int iErr = ERR_SUCCESS;
    FILE *fp = NULL;
    int sum = 0;
        int xx = 0;

    do 
    {
        keylen = strlen((char*) szPublicKey);
        unsigned char szBuffer[keylen];
        keylen = EVP_DecodeBlock(szBuffer, (unsigned char*)szPublicKey, strlen((char*)szPublicKey));
        p = szBuffer;

        pkey = d2i_PUBKEY (&pkey, &p, keylen);
        if (NULL == pkey)
        {
            PRINT_ERROR ("d2i_PUBKEY failed");
            printf ("openssl err:%s\n", LOCKET_ERR_GetString ());
            iErr = ERR_FAILED;
            break;
        }

        /* we can not get ciphertext length from plaintext
         * so malloc the max buffer
         */
        outlen = 10*1024*1024;
        if (!(outbuf = malloc(outlen))) {
            PRINT_ERROR("malloc failed");
            iErr = ERR_FAILED;
            break;
        }

        if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
            PRINT_ERROR("EVP_PKEY_CTX_new failed");
            printf ("openssl err:%s\n", LOCKET_ERR_GetString ());
            iErr = ERR_FAILED;
            break;
        }

        if (!EVP_PKEY_encrypt_init(pkctx)) {
            PRINT_ERROR("EVP_PKEY_encrypt_init failed");
            iErr = ERR_FAILED;
            break;
        }
        if (!EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PADDING))
        {
            printf ("padding set failed\n");
        }

#if 1
        fp = fopen ("test.txt", "rb");
        if (NULL == fp)
        {
            printf ("fopen failed\n");
            exit (1);
        }
#endif
        int nread = 0;
        do 
        {
            char buffer[128] = {0};
            nread = fread (buffer, 1, 117, fp);
            if (0 == nread)
            {
                printf ("fread finish\n");
                break;
            }

            if (!EVP_PKEY_encrypt(pkctx, outbuf+xx, &outlen, (unsigned char*)buffer, nread)) {
                PRINT_ERROR("EVP_PKEY_encrypt failed");
                printf ("openssl err:%s\n", LOCKET_ERR_GetString ());
                iErr = ERR_FAILED;
                exit (1);
            }
            xx += outlen;
            printf ("outlen:%lu\n", outlen);
        } while (1);


        fclose(fp);
    } while (0);

    do 
    {
        unsigned char *in = outbuf;
        keylen = strlen((char*) szPrivateKey);
        unsigned char szBuffer[keylen];
        keylen = EVP_DecodeBlock(szBuffer, (unsigned char*)szPrivateKey, strlen((char*)szPrivateKey));

        p = szBuffer;
        pkey = d2i_AutoPrivateKey(NULL, &p, keylen);
        if (NULL == pkey)
        {
            PRINT_ERROR ("d2i_AutoPrivateKey failed");
            iErr = ERR_FAILED;
            break;
        }

        /* we can not get ciphertext length from plaintext
         * so malloc the max buffer
         */
        
        if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
            PRINT_ERROR("EVP_PKEY_CTX_new failed");
            iErr = ERR_FAILED;
            break;
        }

        if (!EVP_PKEY_decrypt_init(pkctx)) {
            PRINT_ERROR("EVP_PKEY_encrypt_init failed");
            iErr = ERR_FAILED;
            break;
        }
        if (!EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PADDING))
        {
            printf ("padding set failed\n");
        }

        char outbuf2[8096] = {0};
        int outlen2 = 0;
        int tmplen = 256;
        int j = 0;
        int blksize = 128;
        printf ("xx:%d\n", xx);
        do
        {
            tmplen = 256;
            if (!EVP_PKEY_decrypt(pkctx, (unsigned char*)outbuf2, (size_t*)&tmplen, (unsigned char*)in + j*blksize, blksize)) {
                printf ("openssl err:%s\n", LOCKET_ERR_GetString ());
                PRINT_ERROR("EVP_PKEY_decrypt failed");
                iErr = ERR_FAILED;
                break;
            }
            printf ("outbuf2:%s, tmplen:%d\n", outbuf2, tmplen);
            if ((j+1)*blksize == xx)
            {
                break;
            }
            j++;
        } while (1);

    } while (0);

    return;
}


#define READ_SIZE  1024*1024*10
char gbuffer[READ_SIZE] = {0};
char gbuffer2[READ_SIZE] = {0};
void sm2_test_large_file (char szPublicKey[], char szPrivateKey[])
{
	size_t keylen, outlen;
	const unsigned char *p = NULL;
    unsigned char *outbuf = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkctx = NULL;
    int iErr = ERR_SUCCESS;
    FILE *fp = NULL;
    int sum = 0;
        int xx = 0;
        int yy = 0;

    do 
    {
        keylen = strlen((char*) szPublicKey);
        unsigned char szBuffer[keylen];
        keylen = EVP_DecodeBlock(szBuffer, (unsigned char*)szPublicKey, strlen((char*)szPublicKey));
        p = szBuffer;

        pkey = d2i_PUBKEY (&pkey, &p, keylen);
        if (NULL == pkey)
        {
            PRINT_ERROR ("d2i_PUBKEY failed");
            printf ("openssl err:%s\n", LOCKET_ERR_GetString ());
            iErr = ERR_FAILED;
            break;
        }

        /* we can not get ciphertext length from plaintext
         * so malloc the max buffer
         */
        outlen = READ_SIZE;
        if (!(outbuf = malloc(outlen))) {
            PRINT_ERROR("malloc failed");
            iErr = ERR_FAILED;
            break;
        }

        if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
            PRINT_ERROR("EVP_PKEY_CTX_new failed");
            printf ("openssl err:%s\n", LOCKET_ERR_GetString ());
            iErr = ERR_FAILED;
            break;
        }

        if (!EVP_PKEY_encrypt_init(pkctx)) {
            PRINT_ERROR("EVP_PKEY_encrypt_init failed");
            iErr = ERR_FAILED;
            break;
        }
#if 1
        fp = fopen ("test.txt", "rb");
        if (NULL == fp)
        {
            printf ("fopen failed\n");
            exit (1);
        }
#endif
        int nread = 0;
        /* SM2和RSA不一样,前者最大一次性能加密4MB的数据, 无法分段加密, 后者则是由RSA_SIZE决定，
         * 因为RSA有PADDING方式，所以可以分段加密, 和固定大小数据段解密 
         */
        do 
        {
            nread = fread (gbuffer, 1, READ_SIZE, fp);
            if (0 == nread)
            {
                printf ("fread finish\n");
                break;
            }

            if (!EVP_PKEY_encrypt(pkctx, outbuf+xx, &outlen, (unsigned char*)gbuffer, nread)) {
                PRINT_ERROR("EVP_PKEY_encrypt failed");
                printf ("openssl err:%s\n", LOCKET_ERR_GetString ());
                iErr = ERR_FAILED;
                exit (1);
            }
            xx += outlen;
            yy += nread;
        } while (0);
        printf ("total read :%lu\n", yy);
        printf ("total sm2 encrypt output:%lu\n", xx);


    fclose(fp);
    } while (0);


    do 
    {
        unsigned char *in = outbuf;
        keylen = strlen((char*) szPrivateKey);
        unsigned char szBuffer[keylen];
        keylen = EVP_DecodeBlock(szBuffer, (unsigned char*)szPrivateKey, strlen((char*)szPrivateKey));

        p = szBuffer;
        pkey = d2i_AutoPrivateKey(NULL, &p, keylen);
        if (NULL == pkey)
        {
            PRINT_ERROR ("d2i_AutoPrivateKey failed");
            iErr = ERR_FAILED;
            break;
        }

        /* we can not get ciphertext length from plaintext
         * so malloc the max buffer
         */
        
        if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
            PRINT_ERROR("EVP_PKEY_CTX_new failed");
            iErr = ERR_FAILED;
            break;
        }

        if (!EVP_PKEY_decrypt_init(pkctx)) {
            PRINT_ERROR("EVP_PKEY_encrypt_init failed");
            iErr = ERR_FAILED;
            break;
        }
        if (!EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PADDING))
        {
            printf ("padding set failed\n");
        }

        int tmplen = sizeof (gbuffer2);
        do
        {
            if (!EVP_PKEY_decrypt(pkctx, (unsigned char*)gbuffer2, (size_t*)&tmplen, (unsigned char*)in, xx) ){
                printf ("openssl err:%s\n", LOCKET_ERR_GetString ());
                PRINT_ERROR("EVP_PKEY_decrypt failed");
                iErr = ERR_FAILED;
                break;
            }
            printf ("%s\n", gbuffer2);
            printf ("total in buffer :%lu\n", xx);
            printf ("total sm2 decrypt output:%lu\n", tmplen);
            break;
        } while (1);

    } while (0);

    return;
}

int main()
{
    ERR_load_crypto_strings ();
    OpenSSL_add_all_algorithms ();

    char szPublicKey[1024] = {0};
    char szPrivateKey[1024] = {0};
    printf ("[SM2]\n");
    (void) gen_sm2_key_pair (szPublicKey, szPrivateKey);

    printf ("[SM2-Crypt]\n");
    (void) sm2_crypt (szPublicKey, szPrivateKey);

    printf ("[SM2-Sign]\n");
    char in[] = "helloworld2";
    char szSign[1024] = {0};
    int signlen = 0;
    (void) asymmetric_sign (szPrivateKey, in, strlen(in), szSign, &signlen);
    (void) asymmetric_verify (szPublicKey, szSign, signlen, in, strlen(in));
    sm2_test_large_file (szPublicKey, szPrivateKey);
    
    
    int keylen = 1024;
    char szRSAPublicKey[keylen];
    char szRSAPrivateKey[keylen];
    memset (szRSAPublicKey, 0 ,sizeof (szRSAPublicKey));
    memset (szRSAPrivateKey, 0 ,sizeof (szRSAPrivateKey));
    printf ("\n[RSA-%d]\n", keylen);
    (void) gen_rsa_key_pair (szRSAPublicKey, szRSAPrivateKey, keylen);
    (void) rsa_crypt (szRSAPublicKey, szRSAPrivateKey);

    char szrsasign[4096] = {0};
    int rsasignlen = 0;
    (void) asymmetric_sign (szPrivateKey, in, strlen(in), szrsasign, &rsasignlen);
    (void) asymmetric_verify (szPublicKey, szrsasign, rsasignlen, in, strlen(in));
    rsa_test_large_file (szRSAPublicKey, szRSAPrivateKey);


    

    return 0;
}
