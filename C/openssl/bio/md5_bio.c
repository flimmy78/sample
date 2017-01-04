#include <openssl/evp.h>

int main()

{

	BIO *bmd=NULL,*b=NULL;

	const EVP_MD *md=EVP_md5();

	int len;

	char tmp[1024];

	bmd=BIO_new(BIO_f_md());

	BIO_set_md(bmd,md);

	b= BIO_new(BIO_s_null());

	b=BIO_push(bmd,b);

	len=BIO_write(b,"openssl",7);

	len=BIO_gets(b,tmp,1024);

    BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_write (out, tmp, len);

    BIO_free(out);
	BIO_free(b);

	return 0;

}
