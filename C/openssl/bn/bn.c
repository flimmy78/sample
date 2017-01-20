#include <openssl/bn.h>
#include <openssl/bio.h>

void dec2bn (BIO *bfp, BIGNUM *bn)
{
    /* 十进制转换成BN */
    int num = BN_dec2bn(&bn, "1234567890");
    if (0 == num)
    {
        printf ("BN_dec2bn failed\n");
        BN_free (bn);
        return;
    }

    /* num表示BN的位数 */
    //BIO_printf(bfp, "num:%d\n", num);

    /* 输出大数到bio中, 输出格式默认16进制 */
    //BN_print(bfp, bn);
    //BIO_printf (bfp, "\n");

    /* bn->hex */
    char *bnhex = BN_bn2hex (bn);
    //BIO_printf (bfp, "bnhex:%s\n", bnhex);

    /* bn->dec */
    char *bndec = BN_bn2dec (bn);
    //BIO_printf (bfp, "bndec:%s\n", bndec);

    /* 需要释放BIGNUM */
    BN_free (bn);

    return;
}

void bnadd (BIO *bfp)
{
    BIGNUM *bn1 = NULL;
    BIGNUM *bn2 = NULL;

    /* 16进制转换成BN */
    (void) BN_hex2bn(&bn1, "abcdef");
    (void) BN_hex2bn(&bn2, "fedcba");

    BIGNUM *bn3 = BN_new ();
    if (NULL == bn3)
    {
        BN_free (bn1);
        BN_free (bn2);
        return;
    }
    
    (void) BN_add (bn3, bn1, bn2);

    char *dec = BN_bn2dec (bn3);

    (void) BIO_printf (bfp, "bn1 + bn2 = %s\n", dec);

    BN_free (bn1);
    BN_free (bn2);
    BN_free (bn3);
    return;
}

void hex2bn (BIO *bfp, BIGNUM *bn)
{
    /* 16进制转换成BN */
    int num = BN_hex2bn(&bn, "abcdef");
    if (0 == num)
    {
        printf ("BN_hex2bn failed\n");
        BN_free (bn);
        return;
    }

    /* 输出大数到bio中 */
    //BN_print(bfp, bn);

    /* 需要释放BIGNUM */
    BN_free (bn);

    return;
}

void genprime (BIO *bfp)
{
    BIGNUM *bn = BN_new ();

    if (!BN_generate_prime_ex(bn, 512, 0, NULL, NULL, NULL))
    {
        printf ("gen prime failed\n");
        BN_free (bn);
        return;
    }

    /* 512指的是位数(二进制) */
    //BN_print(bfp, bn);

    BN_free (bn);
    return;
}

void genrand (BIO *bfp)
{
    BIGNUM *bn = BN_new ();

    BN_rand (bn, 5, 0, 0);

    BN_print(bfp, bn);

    BN_free (bn);
    return;
}

int main()
{
    BIGNUM *bn = NULL;

    /* 创建fp类型 BIO */
    BIO *bfp = BIO_new_fp (stdout, BIO_NOCLOSE);

    dec2bn (bfp, bn);
    hex2bn (bfp, bn);
   
    bnadd (bfp); 

    genprime (bfp);

    genrand (bfp);

    /* 需要释放BIO */
    BIO_free (bfp);

    return 0;
}
