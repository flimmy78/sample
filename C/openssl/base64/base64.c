#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

void base64 (BIO *bfp)
{
    unsigned char out[1024] = {0};
    unsigned char in[512] = "hello,world";

    /* 结果中不会包含换行符, 返回的out会携带'\0', 所以实际使用过程当中buffer大小一定要足够 */
    /* 此外, len返回的长度，不包含'\0' */
    int len = EVP_EncodeBlock (out , in, strlen ((char*)in));
    BIO_printf (bfp, "encoded base64 string:%s, length:%d\n", out, len);

    /* 解码时，返回的结果携带'\0' */
    /* 此外，len返回的长度，是包含结束符'\0'这个字节的 */
    unsigned char dec[1024] = {0};
    
    unsigned char tmp[] = "   aGVsbG8sd29ybGQ=\r\n";
    if (-1 != (len = EVP_DecodeBlock (dec,  tmp, strlen((char*)tmp))))
    {
        BIO_printf (bfp, "decoded plain string:%s, length:%d\n", dec, len);
    }

    return;
}
int main()
{
    /* 创建fp类型 BIO */
    BIO *bfp = BIO_new_fp (stdout, BIO_NOCLOSE);

    base64 (bfp);
    

    /* 需要释放BIO */
    BIO_free (bfp);

    return 0;
}
