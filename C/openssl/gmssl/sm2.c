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

EVP_PKEY *gen_ec_key_pair(void)
{
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

    char szPublicKey[1024] = {0};
    get_sm2_public_key (pstKey, szPublicKey);
    printf ("SM2 Public Key:%s\n", szPublicKey);

    char szPrivateKey[1024] = {0};
    get_sm2_private_key (pstKey, szPrivateKey);
    printf ("SM2 Private Key:%s\n", szPrivateKey);

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

int main()
{
    ERR_load_crypto_strings ();
    OpenSSL_add_all_algorithms ();

    (void) gen_ec_key_pair ();

    return 0;
}
