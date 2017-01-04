#include <stdio.h>
#include <string.h>

#include "openssl/evp.h"


int main()
{
    OpenSSL_add_all_algorithms();

    char *pcAlgo = "MD5";
    const EVP_MD *pstMd = EVP_get_digestbyname (pcAlgo);
    if (NULL == pstMd)
    {
        printf ("get algo:%s failed\n", pcAlgo);
        return 0;
    }


    EVP_MD_CTX *pstDigestCtx = EVP_MD_CTX_new ();
    if (NULL == pstDigestCtx)
    {
        printf ("get algo:%s failed\n", pcAlgo);
        return 0;
    }

    int iErr = EVP_DigestInit_ex(pstDigestCtx,pstMd, NULL);
    if (!iErr)
    {
        printf ("init algo:%s failed\n", pcAlgo);
        return 0;
    }

    const char *input = "hello,world";
    char szOutput[33] = {0};
    int inlen = (int) strlen(input);
    int outlen = 0;

    int i = 0; 
    for (i = 0; i < inlen; i++)
    {
        iErr = EVP_DigestUpdate (pstDigestCtx,  &input[i], 1);
        if (!iErr)
        {
            printf ("digest update failed\n");
            return 0;
        }
    }

    iErr = EVP_DigestFinal_ex(pstDigestCtx, (unsigned char*) szOutput, (unsigned int*) &outlen);
    if (!iErr)
    {
        printf ("digest final failed\n");
        return 0;
    }

    printf ("outlen:%d\n", outlen);
    for (i = 0; i < outlen; i++)
    {
        printf ("%02x", (unsigned char)szOutput[i]);
    }
    printf ("\n");


    
}

