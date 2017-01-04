#include <stdio.h>
#include <string.h>
#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/err.h"
unsigned char szInput[16] = "helloworld";
unsigned char szEncryptOut[64] = {0};
unsigned char szDecryptOut[64] = {0};
char *pCipher = "SMS4-ECB";

static int encrypt (char *pCipher )
{
    memset (szEncryptOut, 0, sizeof (szEncryptOut));
    memset (szDecryptOut, 0, sizeof (szDecryptOut));
    const EVP_CIPHER *pstCipher  = NULL;
    pstCipher    = EVP_get_cipherbyname(pCipher);
    if (NULL == pstCipher)
    {
        printf ("get ciper:%s failed\n", pCipher);
        return 0;
    }

    EVP_CIPHER_CTX *pstCipherCtx = NULL;
    pstCipherCtx = EVP_CIPHER_CTX_new ();

    unsigned char szKey[] = "1234567890123456"; 
    unsigned char szIv[] =  "1234567890123456";

    int iErr = 1;
    iErr = EVP_CipherInit_ex(pstCipherCtx, pstCipher, NULL, szKey, szIv, 1);
    if (1 != iErr)
    {
        printf ("iErr:%d\n", iErr);
        printf ("EVP_CipherInit_ex failed\n");
        return 0;
    }

    int inputlen = 0;
    int outputlen = 0;

    iErr = EVP_CipherUpdate(pstCipherCtx, szEncryptOut, &outputlen, szInput, strlen((char*)szInput));
    if (1 != iErr)
    {
        printf ("iErr:%d\n", iErr);
        printf ("EVP_CipherUpdate failed\n");
        return 0;
    }

    int outputlen2 = 0;
    iErr = EVP_CipherFinal_ex(pstCipherCtx, szEncryptOut+outputlen, &outputlen2);
    if (1 != iErr)
    {
        printf ("iErr:%d\n", iErr);
        printf ("EVP_CipherFinal_ex failed\n");
        return 0;
    }

    printf ("Mode:%s\n", pCipher);
    printf ("len:%d    ", outputlen + outputlen2);
    printf ("cryptText:");
    int i = 0; 
    for (i = 0; i < (outputlen + outputlen2); i ++)
    {
        printf ("%02x", szEncryptOut[i]);
    }
    printf ("\n");

    return 1;
}

static int decrypt (char *pCipher)
{
    const EVP_CIPHER *pstCipher  = NULL;
    pstCipher    = EVP_get_cipherbyname(pCipher);
    if (NULL == pstCipher)
    {
        printf ("get ciper:%s failed\n", pCipher);
        return 0;
    }

    EVP_CIPHER_CTX *pstCipherCtx = NULL;
    pstCipherCtx = EVP_CIPHER_CTX_new ();

    unsigned char szKey[] = "1234567890123456"; 
    unsigned char szIv[] =  "1234567890123456";

    int iErr = 1;
    iErr = EVP_CipherInit_ex(pstCipherCtx, pstCipher, NULL, szKey, szIv, 0);
    if (1 != iErr)
    {
        printf ("iErr:%d\n", iErr);
        printf ("EVP_CipherInit_ex failed\n");
        return 0;
    }

    int inputlen = 0;
    int outputlen = 0;

    iErr = EVP_CipherUpdate(pstCipherCtx, szDecryptOut, &outputlen, szEncryptOut, strlen((char*)szEncryptOut));
    if (1 != iErr)
    {
        printf ("iErr:%d\n", iErr);
        printf ("EVP_CipherUpdate failed\n");
        return 0;
    }

    int outputlen2 = 0;
    iErr = EVP_CipherFinal_ex(pstCipherCtx, szDecryptOut+outputlen, &outputlen2);
    if (1 != iErr)
    {
        printf ("iErr:%d\n", iErr);
        printf ("EVP_CipherFinal_ex failed\n");
        return 0;
    }

    printf ("len:%d    ", outputlen + outputlen2);
    printf ("plainText:%s\n", szDecryptOut);

    return 1;
}
int main()
{
    ERR_load_crypto_strings ();
    OpenSSL_add_all_algorithms ();

    pCipher = "SMS4-ECB";
    encrypt (pCipher);
    decrypt (pCipher);

    pCipher = "SMS4-CBC";
    encrypt (pCipher);
    decrypt (pCipher);

    pCipher = "SMS4-CFB";
    encrypt (pCipher);
    decrypt (pCipher);

    pCipher = "SMS4-OFB";
    encrypt (pCipher);
    decrypt (pCipher);

    pCipher = "SMS4-CTR";
    encrypt (pCipher);
    decrypt (pCipher);
    
    return 0;
}
