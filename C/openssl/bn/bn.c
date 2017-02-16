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

    /* BIGNUM *BN_generate_prime(BIGNUM *ret, int num, int safe, BIGNUM *add,
     *             BIGNUM *rem, void (*callback)(int, int, void *), void *cb_arg); */
    /* safe = 1的时候，满足安全素数, (p-1)/2 依然是素数 */
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

    BIO_printf (bfp, "[test BN_rand]\n");
    /* int BN_rand(BIGNUM *rnd, int bits, int top, int bottom); */
    /* top = 0, 结果最高位保持1 */
    /* top = -1, 结果最高位可以是0，也可以是1 */
    /* top = 1, 最高两位都是1 */
    /* bottom = 0, 结果可能是偶数，也会是奇数 */
    /* bottom = 1, 结果始终为奇数 */
    BN_rand (bn, 5, 1, 0);

    BN_print(bfp, bn);
    BIO_printf (bfp, "\n");

    BN_free (bn);
    return;
}

void setbignum (BIO *bfp)
{
    BIGNUM *bn = BN_new ();

    unsigned long w = 0x12345678;
    if (! BN_set_word (bn, w))
    {
        printf ("BN_set_word failed\n");
        BN_free (bn);
        return;
    }

    BN_print (bfp, bn);

    BN_free (bn);
    return;
}

void bnoptions (BIO *bfp)
{
    /* test BN_ULLONG BN_ULONG size */
    BIO_printf (bfp, "[test BN_options]\n");

    BIO_printf (bfp, "%s", BN_options ());

    BIO_printf (bfp, "\n");

    return;
}

void getbnbitsnum (BIO *bfp)
{
    BIGNUM *bn = BN_new ();

    unsigned long w = 0x12345678;
    if (! BN_set_word (bn, w))
    {
        printf ("BN_set_word failed\n");
        BN_free (bn);
        return;
    }

    BIO_printf (bfp, "bn bits num:%d\n", BN_num_bits(bn));

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

    setbignum (bfp); 

    bnoptions (bfp);

    getbnbitsnum (bfp);

    /* 需要释放BIO */
    BIO_free (bfp);

    return 0;
}
