#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <limits.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define DEBUG 1

/********************************************
功能：搜索字符串右边起的第一个匹配字符
********************************************/
char *Rstrchr(char *s, char x)
{
    int i = strlen(s);
    if (!(*s))
        return 0;
    while (s[i - 1])
        if (strchr(s + (i - 1), x))
            return (s + (i - 1));
        else
            i--;
    return 0;
}

/**************************************************************
功能：从字符串src中分析出网站地址和端口，并得到用户要下载的文件
***************************************************************/
void GetHost(char *src, char *web, char *file, int *port)
{
    char *pA;
    char *pB;
    *port = 0;
    if (!(*src))
        return;
    pA = src;
    if (!strncmp(pA, "http://", strlen("http://")))
        pA = src + strlen("http://");
    else if (!strncmp(pA, "https://", strlen("https://")))
        pA = src + strlen("https://");
    pB = strchr(pA, '/');
    if (pB) {
        memcpy(web, pA, strlen(pA) - strlen(pB));
        if (pB + 1) {
            memcpy(file, pB + 1, strlen(pB) - 1);
            file[strlen(pB) - 1] = 0;
        }
    } else
        memcpy(web, pA, strlen(pA));
    if (pB)
        web[strlen(pA) - strlen(pB)] = 0;
    else
        web[strlen(pA)] = 0;
    pA = strchr(web, ':');
    if (pA)
        *port = atoi(pA + 1);
    else
        *port = 443;
    printf ("port:%d\n", *port);
}

/************关于本文档********************************************
*filename: https-client.c
*purpose: 演示HTTPS客户端编程方法
*wrote by: zhoulifa(zhoulifa@163.com) 周立发(http://zhoulifa.bokee.com)
Linux爱好者 Linux知识传播者 SOHO族 开发者 最擅长C语言
*date time:2007-01-30 20:06
*Note: 任何人可以任意复制代码并运用这些文档，当然包括你的商业用途
* 但请遵循GPL
*Thanks to:Google
*Hope:希望越来越多的人贡献自己的力量，为科学技术发展出力
* 科技站在巨人的肩膀上进步更快！感谢有开源前辈的贡献！
*********************************************************************/

int main(int argc, char *argv[])
{
    int sockfd, ret;
    char buffer[1024];
    struct sockaddr_in server_addr;
    struct hostent *host;
    int portnumber, nbytes;
    char host_addr[256] = {0};
    char host_file[1024] = {0};
    char local_file[256] = {0};
    FILE *fp;
    char request[1024] = {0};
    int send, totalsend;
    int i;
    char *pt;
    SSL *ssl;
    SSL_CTX *ctx;

    if (argc != 2) {
        if (DEBUG)
            fprintf(stderr, "Usage:%s webpage-address\a\n", argv[0]);
        exit(1);
    }
    if (DEBUG)
        printf("parameter.1 is: %s\n", argv[1]);

    GetHost(argv[1], host_addr, host_file, &portnumber);        /*分析网址、端口、文件名等 */
    if (DEBUG)
        printf("webhost:%s\n", host_addr);
    if (DEBUG)
        printf("hostfile:%s\n", host_file);
    if (DEBUG)
        printf("portnumber:%d\n\n", portnumber);

    if ((host = gethostbyname(host_addr)) == NULL) {        /*取得主机IP地址 */
        if (DEBUG)
            fprintf(stderr, "Gethostname error, %s\n", strerror(errno));
        exit(1);
    }

    /* 客户程序开始建立 sockfd描述符 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {        /*建立SOCKET连接 */
        if (DEBUG)
            fprintf(stderr, "Socket Error:%s\a\n", strerror(errno));
        exit(1);
    }

    /* 客户程序填充服务端的资料 */
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(portnumber);
    server_addr.sin_addr = *((struct in_addr *) host->h_addr);

    /* 客户程序发起连接请求 */
    if (connect(sockfd, (struct sockaddr *) (&server_addr), sizeof(struct sockaddr)) == -1) {        /*连接网站 */
        if (DEBUG)
            fprintf(stderr, "Connect Error:%s\a\n", strerror(errno));
        exit(1);
    }

    /* SSL初始化 */
    SSL_library_init();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); 
#if 1
    int iret = SSL_CTX_load_verify_locations(ctx, "cacert.pem", NULL);
    if (iret != 1)
    {
        ERR_print_errors_fp(stderr);
        exit (1);
    }
#endif 



    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    /* 把socket和SSL关联 */
    ret = SSL_set_fd(ssl, sockfd);
    if (ret == 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    RAND_poll();
    while (RAND_status() == 0) {
        unsigned short rand_ret = rand() % 65536;
        RAND_seed(&rand_ret, sizeof(rand_ret));
    }

    ret = SSL_connect(ssl);
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    sprintf(request, "GET /%s HTTP/1.1\r\nAccept: */*\r\nAccept-Language: zh-cn\r\n\
User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)\r\n\
Host: %s:%d\r\nConnection: Close\r\n\r\n", host_file, host_addr,
            portnumber);
    if (DEBUG)
        printf("%s", request);        /*准备request，将要发送给主机 */

    /*取得真实的文件名 */
    if (*host_file)
        pt = Rstrchr(host_file, '/');
    else
        pt = 0;

    memset(local_file, 0, sizeof(local_file));
    if (pt && *pt) {
        if ((pt + 1) && *(pt + 1))
            strcpy(local_file, pt + 1);
        else
            memcpy(local_file, host_file, strlen(host_file) - 1);
    } else if (*host_file)
        strcpy(local_file, host_file);
    else
        strcpy(local_file, "index.html");
    if (DEBUG)
        printf("local filename to write:%s\n\n", local_file);

    /*发送https请求request */
    send = 0;
    totalsend = 0;
    nbytes = strlen(request);
    while (totalsend < nbytes) {
        send = SSL_write(ssl, request + totalsend, nbytes - totalsend);
        if (send == -1) {
            if (DEBUG)
                ERR_print_errors_fp(stderr);
            exit(0);
        }
        totalsend += send;
        if (DEBUG)
            printf("%d bytes send OK!\n", totalsend);
    }

    fp = fopen(local_file, "a");
    if (!fp) {
        if (DEBUG)
            printf("create file error! %s\n", strerror(errno));
        return 0;
    }
    if (DEBUG)
        printf("\nThe following is the response header:\n");
    i = 0;
    /* 连接成功了，接收https响应，response */
    while ((nbytes = SSL_read(ssl, buffer, 1)) == 1) {
        if (i < 4) {
            if (buffer[0] == '\r' || buffer[0] == '\n')
                i++;
            else
                i = 0;
            if (DEBUG)
                printf("%c", buffer[0]);        /*把https头信息打印在屏幕上 */
        } else {
            fwrite(buffer, 1, 1, fp);        /*将https主体信息写入文件 */
            i++;
            if (i % 1024 == 0)
                fflush(fp);        /*每1K时存盘一次 */
        }
    }
    fclose(fp);
    /* 结束通讯 */
    ret = SSL_shutdown(ssl);
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    close(sockfd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_free_strings();
    exit(0);
}
