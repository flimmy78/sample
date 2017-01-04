/*
  A trivial static http webserver using Libevent's evhttp.

  This is not the best code in the world, and it does some fairly stupid stuff
  that you would never want to do in a production webserver. Caveat hackor!

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#ifndef S_ISDIR
#define S_ISDIR(x) (((x) & S_IFMT) == S_IFDIR)
#endif
#else
#include <sys/stat.h>
#include <sys/socket.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#endif

#include <event2/event.h>
#include <event2/http.h>
#include <event2/http_struct.h>
#include <event2/http_compat.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>
#include <event2/http-internal.h>
#include <sys/queue.h>

#ifdef _EVENT_HAVE_NETINET_IN_H
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#endif

/* include zlib */
#include "zlib.h"

/* Compatibility for possible missing IPv6 declarations */
//#include "../util-internal.h"

#ifdef WIN32
#define stat _stat
#define fstat _fstat
#define open _open
#define close _close
#define O_RDONLY _O_RDONLY
#endif

static int bInit = 0;
char uri_root[512];
struct event_base *base;
static char* gpcServerHost = NULL;
static int giServerHost    = 0;
#define SERVER_HOST             gpcServerHost
#define SERVER_PORT             giServerHost
#define PROXY_TIMEOUT_IN_SECS   60

typedef struct tagHttpConnect
{
    struct evhttp_request *client_request;
    struct evhttp_request *server_request;
    int bSendData;
}connect_info_s;

/* Uncompress gzip data */
/* zdata 数据 nzdata 原数据长度 data 解压后数据 ndata 解压后长度 */
int gzdecompress(Byte *zdata, uLong nzdata, Byte *data, uLong *ndata)
{
    int err = 0;
    z_stream d_stream = {0}; /* decompression stream */
    static char dummy_head[2] = {
        0x8 + 0x7 * 0x10,
        (((0x8 + 0x7 * 0x10) * 0x100 + 30) / 31 * 31) & 0xFF,
    };
    d_stream.zalloc = NULL;
    d_stream.zfree = NULL;
    d_stream.opaque = NULL;
    d_stream.next_in  = zdata;
    d_stream.avail_in = 0;
    d_stream.next_out = data;
    //只有设置为MAX_WBITS + 16才能在解压带header和trailer的文本
#if 0
    if(inflateInit2(&d_stream, MAX_WBITS + 16) != Z_OK) 
    {
        printf ("inflateInit2 failed\n");
        return -1;
    }
#endif
    if(inflateInit2(&d_stream, 47) != Z_OK) 
    {
        printf ("****inflateInit2 failed\n");
        return -1;
    }
    while(d_stream.total_out < *ndata && d_stream.total_in < nzdata) 
    {
        d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
        if ((err = inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END) 
        {
            break;
        }

        if(err != Z_OK) 
        {
            if(err == Z_DATA_ERROR) 
            {
                d_stream.next_in = (Bytef*) dummy_head;
                d_stream.avail_in = sizeof(dummy_head);
                if ((err = inflate(&d_stream, Z_NO_FLUSH)) != Z_OK)
                {
                    printf ("inflate error\n");
                    return -1;
                }
            } 
            else 
            {
                printf ("err :%d\n", err);
                return -1;
            }
        }
    }

    if(inflateEnd(&d_stream) != Z_OK)
    {
        printf ("inflateEnd error\n");
        return -1;
    }

    *ndata = d_stream.total_out;
    return 0;
}

/* Callback used for the /dump URI, and for every non-GET request:
 * dumps all information to stdout and gives back a trivial 200 ok */
static void dump_request_cb(struct evhttp_request *req, void *arg)
{
	const char *cmdtype;
	struct evkeyvalq *headers;
	struct evkeyval *header;
	struct evbuffer *buf;

	switch (evhttp_request_get_command(req)) {
	case EVHTTP_REQ_GET: cmdtype = "GET"; break;
	case EVHTTP_REQ_POST: cmdtype = "POST"; break;
	case EVHTTP_REQ_HEAD: cmdtype = "HEAD"; break;
	case EVHTTP_REQ_PUT: cmdtype = "PUT"; break;
	case EVHTTP_REQ_DELETE: cmdtype = "DELETE"; break;
	case EVHTTP_REQ_OPTIONS: cmdtype = "OPTIONS"; break;
	case EVHTTP_REQ_TRACE: cmdtype = "TRACE"; break;
	case EVHTTP_REQ_CONNECT: cmdtype = "CONNECT"; break;
	case EVHTTP_REQ_PATCH: cmdtype = "PATCH"; break;
	default: cmdtype = "unknown"; break;
	}

	printf("Received a %s request for %s\nHeaders:\n",
	    cmdtype, evhttp_request_get_uri(req));

    printf("  Proxy Host:%s\n", SERVER_HOST);
    printf("  Proxy Port:%d\n", SERVER_PORT);
	headers = evhttp_request_get_input_headers(req);
	for (header = headers->tqh_first; header;
	    header = header->next.tqe_next) {
		printf("  %s: %s\n", header->key, header->value);
	}

	buf = evhttp_request_get_input_buffer(req);
	puts("Input data: <<<");
	while (evbuffer_get_length(buf)) {
		int n;
		char cbuf[128];
		n = evbuffer_remove(buf, cbuf, sizeof(cbuf));
		if (n > 0)
			(void) fwrite(cbuf, 1, n, stdout);
	}
	puts(">>>");

	evhttp_send_reply(req, 200, "OK", NULL);
} 

// called per chunk received
// chunk回调期间， ntoread = -1; chunk回调结束后，ntoread = 0;
// 如果有chunk数据，chunked = 1
// reqcb结束后,userdone才设置成1, 其他情况均为0
void chunkcb(struct evhttp_request *server_response, void *arg) 
{
    connect_info_s *connect_info = (connect_info_s*)arg;
    struct evhttp_request *client_response = connect_info->client_request;

	if(NULL == server_response)
    {
		fprintf(stdout, "http close");
        /* evhttp_send_reply之后会把数据自动清空, 若第四参数不为NULL,则需要调用者手动释放*/
		evhttp_send_reply(client_response, 504, "Bad Gateway.", NULL);
		return;
	}

    if (0 == connect_info->bSendData)
    {
       connect_info->bSendData = 1;

       struct evkeyval *header;
       TAILQ_FOREACH(header, server_response->input_headers, next) 
       {
           //evhttp_send_reply_start内部会自动添加如下字段，所以此处不需要添加
           if (0 == strncmp (header->key, "Transfer-Encoding", strlen("Transfer-Encoding")))
           {
               continue;
           }

           (void)evhttp_add_header(client_response->output_headers, (const char*)header->key, (const char*)header->value);
       }

       evhttp_send_reply_start (client_response, 200, "OK");
    }

    evhttp_send_reply_chunk (client_response, server_response->input_buffer);

    return;
}

// gets called when request completes
void reqcb(struct evhttp_request * server_response, void * arg) 
{
    connect_info_s *connect_info = (connect_info_s*)arg;
    struct evhttp_request *client_response = connect_info->client_request;

	if(NULL == server_response)
    {
		fprintf(stdout, "http close.");
        /* evhttp_send_reply之后会把数据自动清空, 若第四参数不为NULL,则需要调用者手动释放*/
		evhttp_send_reply(client_response, 504, "Bad Gateway.", NULL);
		return;
	}

    /* 如果没有得到response, libevent会把request返回，以便用户做些错误处理 */
    if (EVHTTP_REQUEST == server_response->kind)
    {
       fprintf (stdout, "http request failed\n");
    }

    if (connect_info->bSendData == 1)
    {
        evhttp_send_reply_end (client_response);
        connect_info->bSendData = 0;
        return;
    }

    return;
}

struct evhttp_request *proxy_request(const char *domain,
                                    unsigned short port,
                                    int timeout_in_secs,
                                    struct evhttp_request *client_request, 
                                    const char *path)
{
    struct evhttp_connection *server_connection = NULL;
    struct evhttp_request *server_request = NULL;
    connect_info_s *connect_info = (connect_info_s*) malloc (sizeof (connect_info_s));
    if (NULL == connect_info)
    {
        return NULL;
    }
    memset (connect_info, 0, sizeof (connect_info_s));

    server_connection = evhttp_connection_base_new(base, NULL, domain, port);
    evhttp_connection_set_timeout(server_connection, timeout_in_secs);//如果放在evhttp_make_request会挂掉
    server_request = evhttp_request_new(reqcb, (void*)connect_info);
    evhttp_request_set_chunked_cb (server_request, chunkcb);

    connect_info->client_request = client_request;

    struct evkeyval *header;
    TAILQ_FOREACH(header, client_request->input_headers, next) 
    {
        if (0 == strncmp (header->key, "Host", strlen("Host")))
        {
            char szHost[128] = {0};
            evutil_snprintf(szHost, sizeof(szHost), "%s:%d",domain,port);

            (void) evhttp_add_header(server_request->output_headers, (const char *)header->key, szHost);
        }
        else
        {
            (void) evhttp_add_header(server_request->output_headers, (const char *)header->key, header->value);
        }
    }
    if (client_request->type == EVHTTP_REQ_POST)
    {
        (void) evbuffer_add_buffer(server_request->output_buffer , client_request->input_buffer);
    }

    int ret = evhttp_make_request(server_connection, server_request, client_request->type, path);
    if (0 != ret)
    {
        printf ("ret:%d\n", ret);
    }
    return server_request;
}

/* This callback gets invoked when we get any http request that doesn't match
 * any other callback.  Like any evhttp server callback, it has a simple job:
 * it must eventually call evhttp_send_error() or evhttp_send_reply().
 */
static void send_document_cb(struct evhttp_request *req, void *arg)
{
    if (NULL == req)
    {
        return;
    }

    /* Parse uri && path */
    const char *uri             = NULL;
    struct evhttp_uri *decoded  = NULL;
    const char *path            = NULL;
    int bUriOK                  = 0; 
    do 
    {
        /* Get uri */
        uri = evhttp_request_get_uri (req);
        if (NULL == uri)
        {
            break;
        }

        /* Decode the URI [scheme:][//host:port][path][?query][#fragment]  */
        decoded = evhttp_uri_parse(uri);
        if (NULL == decoded) 
        {
            break;
        }

        /* Get path  */
        path = evhttp_uri_get_path(decoded);
        if (NULL == path) 
        {
            path = "/";
        }

        bUriOK = 1;
    } while (0);

    if (0 == bUriOK)
    {
        if (NULL != decoded)
        {
            evhttp_uri_free(decoded);
        }

        printf("It's not a good URI. Sending BADREQUEST\n");
        evhttp_send_error(req, HTTP_BADREQUEST, 0);
        return;
    }

    /* Get request type */
    int req_type = evhttp_request_get_command(req);
	if (req_type == EVHTTP_REQ_GET) 
    {
        printf("Got a GET request for <%s>\n",  uri);
	}
    else if (req_type == EVHTTP_REQ_POST)  
    {
        printf("Got a POST request for <%s>\n",  uri);
    }

    /* connect proxy server */
	if (NULL == proxy_request(SERVER_HOST, SERVER_PORT, PROXY_TIMEOUT_IN_SECS, req, path))
    {
		fprintf(stderr, "connect to server fail.");
        evhttp_send_error(req, 502, "Bad Gateway.");
        return;
	}

    /* 必须要在最后释放,因为path指向decoded内容 */
    if (NULL != decoded)
    {
        evhttp_uri_free(decoded);
    }

    return;
}

static void syntax(void)
{
	fprintf(stdout, "Syntax: http-server <docroot>\n");
}

int main(int argc, char **argv)
{
	struct evhttp *http;
	struct evhttp_bound_socket *handle;

	unsigned short port = 8008;
#ifdef WIN32
	WSADATA WSAData;
	WSAStartup(0x101, &WSAData);
#else
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		return (1);
#endif
	if (argc < 2) {
		syntax();
		return 1;
	}

    SERVER_HOST = argv[2];
    SERVER_PORT = atoi (argv[3]);

	base = event_base_new();
	if (!base) {
		fprintf(stderr, "Couldn't create an event_base: exiting\n");
		return 1;
	}

	/* Create a new evhttp object to handle requests. */
	http = evhttp_new(base);
	if (!http) {
		fprintf(stderr, "couldn't create evhttp. Exiting.\n");
		return 1;
	}

	/* The /dump URI will dump all requests to stdout and say 200 ok. */
	evhttp_set_cb(http, "/dump", dump_request_cb, NULL);

	/* We want to accept arbitrary requests, so we need to set a "generic"
	 * cb.  We can also add callbacks for specific paths. */
	evhttp_set_gencb(http, send_document_cb, NULL);

	/* Now we tell the evhttp what port to listen on */
	handle = evhttp_bind_socket_with_handle(http, "0.0.0.0", port);
	if (!handle) {
		fprintf(stderr, "couldn't bind to port %d. Exiting.\n",
		    (int)port);
		return 1;
	}

	{
		/* Extract and display the address we're listening on. */
		struct sockaddr_storage ss;
		evutil_socket_t fd;
		ev_socklen_t socklen = sizeof(ss);
		char addrbuf[128];
		void *inaddr;
		const char *addr;
		int got_port = -1;
		fd = evhttp_bound_socket_get_fd(handle);
		memset(&ss, 0, sizeof(ss));
		if (getsockname(fd, (struct sockaddr *)&ss, &socklen)) {
			perror("getsockname() failed");
			return 1;
		}
		if (ss.ss_family == AF_INET) {
			got_port = ntohs(((struct sockaddr_in*)&ss)->sin_port);
			inaddr = &((struct sockaddr_in*)&ss)->sin_addr;
		} else if (ss.ss_family == AF_INET6) {
			got_port = ntohs(((struct sockaddr_in6*)&ss)->sin6_port);
			inaddr = &((struct sockaddr_in6*)&ss)->sin6_addr;
		} else {
			fprintf(stderr, "Weird address family %d\n",
			    ss.ss_family);
			return 1;
		}
		addr = evutil_inet_ntop(ss.ss_family, inaddr, addrbuf,
		    sizeof(addrbuf));
		if (addr) {
			printf("Listening on %s:%d\n", addr, got_port);
			evutil_snprintf(uri_root, sizeof(uri_root),
			    "http://%s:%d",addr,got_port);
		} else {
			fprintf(stderr, "evutil_inet_ntop failed\n");
			return 1;
		}
	}

	(void) event_base_dispatch(base);
    printf ("event loop exit\n");

    event_base_free(base);

	return 0;
}

#if 0
    size_t len1 = evbuffer_get_length (req->input_buffer);
    printf ("**len1:%d\n", len1);
    unsigned char buf[len1];
    evbuffer_copyout (req->input_buffer,  buf, len1);
    
    int len2 = len1 * 3;
    unsigned char buf2[len2];
    int ret = gzdecompress (buf, len1, buf2, &len2);
    if (ret != 0)
    {
       printf ("ret:%d gzdecompress error\n", ret);
    }

    printf ("**buf2:%s, len2:%d\n", buf2, len2);
#endif
