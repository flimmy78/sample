#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>
using namespace std;

#include <cryptopp/aes.h>
using namespace CryptoPP;

#include <rsa.h>
#include <osrng.h>
#include <cryptlib.h>
#include <queue.h>
#include <hex.h>
#include <modes.h>

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hmac.h"
using CryptoPP::HMAC;

#include "sha.h"
using CryptoPP::SHA256;
using CryptoPP::SHA1;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::HashFilter;
using CryptoPP::HashVerificationFilter;

#include "secblock.h"
using CryptoPP::SecByteBlock;

string aesEncryptBuffer( byte *key ,short keySize ,byte *iv ,byte *text ,size_t textSize)
{

		string ciphertext;
		ciphertext.clear();
		//Encrypt
		CryptoPP::AES::Encryption aesEncryption(key,keySize);
		CryptoPP::CFB_Mode_ExternalCipher::Encryption cfbEncryption(aesEncryption,iv);

		CryptoPP::StreamTransformationFilter stfEncryptor(cfbEncryption,new CryptoPP::StringSink(ciphertext));
		stfEncryptor.Put(reinterpret_cast<const unsigned char*>(text),textSize);
		stfEncryptor.MessageEnd();

		return ciphertext;
}


FILE *encfile = NULL;
typedef enum {
	NALU_TYPE_SLICE    = 1,
	NALU_TYPE_DPA      = 2,
	NALU_TYPE_DPB      = 3,
	NALU_TYPE_DPC      = 4,
	NALU_TYPE_IDR      = 5,
	NALU_TYPE_SEI      = 6,
	NALU_TYPE_SPS      = 7,
	NALU_TYPE_PPS      = 8,
	NALU_TYPE_AUD      = 9,
	NALU_TYPE_EOSEQ    = 10,
	NALU_TYPE_EOSTREAM = 11,
	NALU_TYPE_FILL     = 12,
} NaluType;

typedef enum {
	NALU_PRIORITY_DISPOSABLE = 0,
	NALU_PRIRITY_LOW         = 1,
	NALU_PRIORITY_HIGH       = 2,
	NALU_PRIORITY_HIGHEST    = 3
} NaluPriority;


typedef struct
{
	int startcodeprefix_len;      //! 4 for parameter sets and first slice in picture, 3 for everything else (suggested)
	unsigned len;                 //! Length of the NAL unit (Excluding the start code, which does not belong to the NALU)
	unsigned max_size;            //! Nal Unit Buffer size
	int forbidden_bit;            //! should be always FALSE
	int nal_reference_idc;        //! NALU_PRIORITY_xxxx
	int nal_unit_type;            //! NALU_TYPE_xxxx
	char *buf;                    //! contains the first byte followed by the EBSP
} NALU_t;

FILE *h264bitstream = NULL;                //!< the bit stream file

int info2=0, info3=0;

static int FindStartCode2 (unsigned char *Buf){
	if(Buf[0]!=0 || Buf[1]!=0 || Buf[2] !=1) return 0; //0x000001?
	else return 1;
}

static int FindStartCode3 (unsigned char *Buf){
	if(Buf[0]!=0 || Buf[1]!=0 || Buf[2] !=0 || Buf[3] !=1) return 0;//0x00000001?
	else return 1;
}


int GetAnnexbNALU (NALU_t *nalu){
	int pos = 0;
	int StartCodeFound, rewind;
	unsigned char *Buf;

	if ((Buf = (unsigned char*)calloc (nalu->max_size , sizeof(char))) == NULL)
	{
		printf ("GetAnnexbNALU: Could not allocate Buf memory\n");
		exit (0);
	}

	nalu->startcodeprefix_len=3;

	if (3 != fread (Buf, 1, 3, h264bitstream)){
		free(Buf);
		return 0;
	}
	info2 = FindStartCode2 (Buf);
	if(info2 != 1) {
		if(1 != fread(Buf+3, 1, 1, h264bitstream)){
			free(Buf);
			return 0;
		}
		info3 = FindStartCode3 (Buf);
		if (info3 != 1){
			free(Buf);
			return -1;
		}
		else {
			pos = 4;
			nalu->startcodeprefix_len = 4;
		}
	}
	else{
		nalu->startcodeprefix_len = 3;
		pos = 3;
	}
	StartCodeFound = 0;
	info2 = 0;
	info3 = 0;

	while (!StartCodeFound){
		if (feof (h264bitstream)){
			nalu->len = (pos-1)-nalu->startcodeprefix_len;
			memcpy (nalu->buf, &Buf[nalu->startcodeprefix_len], nalu->len);
			nalu->forbidden_bit = nalu->buf[0] & 0x80; //1 bit
			nalu->nal_reference_idc = nalu->buf[0] & 0x60; // 2 bit
			nalu->nal_unit_type = (nalu->buf[0]) & 0x1f;// 5 bit
			free(Buf);
			return pos-1;
		}
		Buf[pos++] = fgetc (h264bitstream);
		info3 = FindStartCode3(&Buf[pos-4]);
		if(info3 != 1)
			info2 = FindStartCode2(&Buf[pos-3]);
		StartCodeFound = (info2 == 1 || info3 == 1);
	}

	// Here, we have found another start code (and read length of startcode bytes more than we should
	// have.  Hence, go back in the file
	rewind = (info3 == 1)? -4 : -3;

	if (0 != fseek (h264bitstream, rewind, SEEK_CUR)){
		free(Buf);
		printf("GetAnnexbNALU: Cannot fseek in the bit stream file");
	}

	// Here the Start code, the complete NALU, and the next start code is in the Buf.
	// The size of Buf is pos, pos+rewind are the number of bytes excluding the next
	// start code, and (pos+rewind)-startcodeprefix_len is the size of the NALU excluding the start code

	nalu->len = (pos+rewind)-nalu->startcodeprefix_len;
	memcpy (nalu->buf, &Buf[nalu->startcodeprefix_len], nalu->len);//
	nalu->forbidden_bit = nalu->buf[0] & 0x80; //1 bit
	nalu->nal_reference_idc = nalu->buf[0] & 0x60; // 2 bit
	nalu->nal_unit_type = (nalu->buf[0]) & 0x1f;// 5 bit

	/* 加密所有Slice */
	int wsize = 0;
	if (encfile != NULL)
	{
		if ((nalu->nal_unit_type == NALU_TYPE_IDR) || (nalu->nal_unit_type == NALU_TYPE_SLICE))
		{
			byte key[32] = "1234567891234567891234567891234";
			byte iv[16]= "123456789123456";
			string output;
#if 0
			/* i帧数据 */
			output = aesEncryptBuffer (key,sizeof(key), iv, (byte*)&Buf[nalu->startcodeprefix_len],nalu->len );
			memcpy (&Buf[nalu->startcodeprefix_len], output.c_str(), nalu->len);
#endif
			/* i／p帧数据+i／p帧头加密 */
			output = aesEncryptBuffer (key,sizeof(key), iv, (byte*)(Buf + nalu->startcodeprefix_len + 1),nalu->len-1);
			memcpy (Buf+nalu->startcodeprefix_len+1, output.c_str(), nalu->len-1);

			wsize = fwrite (Buf, 1, nalu->len + nalu->startcodeprefix_len,encfile);
			if (wsize < 0)
			{
				printf ("write error\n");
			}
		}
		else
		{
			wsize = fwrite (Buf, 1, nalu->len + nalu->startcodeprefix_len,encfile);
			if (wsize < 0)
			{
				printf ("write error\n");
			}
		}
	}

	free(Buf);

	return (pos+rewind);
}

/**
 * Analysis H.264 Bitstream
 * @param url    Location of input H.264 bitstream file.
 */
int simplest_h264_parser(char *url){

	NALU_t *n;
	int buffersize=1000000;

	//FILE *myout=fopen("output_log.txt","wb+");
	FILE *myout=stdout;

	h264bitstream=fopen(url, "rb+");
	if (h264bitstream==NULL){
		printf("Open file error\n");
		return 0;
	}

	n = (NALU_t*)calloc (1, sizeof (NALU_t));
	if (n == NULL){
		printf("Alloc NALU Error\n");
		return 0;
	}

	n->max_size=buffersize;
	n->buf = (char*)calloc (buffersize, sizeof (char));
	if (n->buf == NULL){
		free (n);
		printf ("AllocNALU: n->buf");
		return 0;
	}

	int data_offset=0;
	int nal_num=0;
	printf("-----+-------- NALU Table ------+---------+\n");
	printf(" NUM |    POS  |    IDC |  TYPE |   LEN   |\n");
	printf("-----+---------+--------+-------+---------+\n");

	int  pframe = 0;
	int dpa = 0;
	int dpb = 0;
	int dpc = 0;
	int iframe = 0;
	int sei = 0;
	int sps = 0;
	int	pps = 0;
	int aud = 0;
	int eoseq = 0;
	int eostream = 0;
	int fill = 0;

	int data_lenth = 0;
		char idc_str[20]={0};
		char type_str[20]={0};
	while(!feof(h264bitstream))
	{
		data_lenth=GetAnnexbNALU(n);

		switch(n->nal_unit_type){
			case NALU_TYPE_SLICE:sprintf(type_str,"SLICE");pframe++;break;
			case NALU_TYPE_DPA:sprintf(type_str,"DPA");dpa++;break;
			case NALU_TYPE_DPB:sprintf(type_str,"DPB");dpb++;break;
			case NALU_TYPE_DPC:sprintf(type_str,"DPC");dpc++;break;
			case NALU_TYPE_IDR:sprintf(type_str,"IDR");iframe++;break;
			case NALU_TYPE_SEI:sprintf(type_str,"SEI");sei++;break;
			case NALU_TYPE_SPS:sprintf(type_str,"SPS");sps++;break;
			case NALU_TYPE_PPS:sprintf(type_str,"PPS");pps++;break;
			case NALU_TYPE_AUD:sprintf(type_str,"AUD");aud++;break;
			case NALU_TYPE_EOSEQ:sprintf(type_str,"EOSEQ");eoseq++;break;
			case NALU_TYPE_EOSTREAM:sprintf(type_str,"EOSTREAM");eostream++;break;
			case NALU_TYPE_FILL:sprintf(type_str,"FILL");fill++;break;
		}
		switch(n->nal_reference_idc>>5){
			case NALU_PRIORITY_DISPOSABLE:sprintf(idc_str,"DISPOS");break;
			case NALU_PRIRITY_LOW:sprintf(idc_str,"LOW");break;
			case NALU_PRIORITY_HIGH:sprintf(idc_str,"HIGH");break;
			case NALU_PRIORITY_HIGHEST:sprintf(idc_str,"HIGHEST");break;
		}

		//fprintf(myout,"%5d| %8d| %7s| %6s| %8d|\n",nal_num,data_offset,idc_str,type_str,n->len);


		data_offset=data_offset+data_lenth;

		nal_num++;
	}
		fprintf(myout,"pframe:%d, dpa:%d, dpb:%d, dpc:%d iframe:%d sei:%d, sps:%d pps:%d aud:%d eoseq:%d eostream:%d fill:%d\n",
				pframe, dpa ,dpb, dpc,iframe,sei,sps,pps,aud,eoseq,eostream,fill);


	if (n){
		if (n->buf){
			free(n->buf);
			n->buf=NULL;
		}
		free (n);
	}
	return 0;
}

int main(int argc, char* argv[])
{
	/* 使用方法： ./a.out 加密前的码流 加密后的码流 */
	if (argc == 3)
	{
		encfile = fopen (argv[2], "wb");
		if (encfile == NULL)
		{
			printf ("open encfile error\n");
			return 0;
		}

	}

	simplest_h264_parser(argv[1]);

	fclose (encfile);
	return 0;
}
