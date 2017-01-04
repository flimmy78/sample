/**********************
 * ToonTonG＠163.com
 * chuantong.huang@gmail.com
 * 2010-11-23
 * 简单的http反向代理
 * *******************/
#include<stdio.h>
#include<stdlib.h>
#include<sys/queue.h>
#include<event.h>
#include<evhttp.h>
char *proxy_host = "www.baidu.com";
unsigned int proxy_port = 80;
int proxy_timeout_in_secs = 60;
// called per chunk received
void chunkcb(struct evhttp_request * req, void * arg) {
	struct evhttp_request *response = (struct evhttp_request *)arg;
	evbuffer_add_buffer(((struct evhttp_request *)arg)->output_buffer , req->input_buffer);
	if (++response->chunked == req->chunked)
	{
		evhttp_send_reply(response, req->response_code, req->response_code_line, req->input_buffer);
		return;
	}
}
// gets called when request completes
void reqcb(struct evhttp_request * req, void * arg) {
	struct evhttp_request *response = (struct evhttp_request*)arg;
	if(!req){
		fprintf(stdout, "http close.");
		evhttp_send_reply(response, 504, "Bad Gateway.", NULL);
		return;
	}
	if (response->chunked)
		return;
	struct evkeyval *header;
	TAILQ_FOREACH(header, req->input_headers, next) {
			evhttp_add_header( response->output_headers,
								(const char *)header->key,
								(const char *)header->value);
	}
	evhttp_send_reply(response, req->response_code, req->response_code_line, req->input_buffer);
	evhttp_send_reply_end(response);
}
struct evhttp_request *proxy_request(const char *domain,
		unsigned short port,
		int timeout_in_secs,
		struct evhttp_request *response)
{
	struct evhttp_connection *evhttp_connection = NULL;
	struct evhttp_request *evhttp_request = NULL;
	evhttp_connection = evhttp_connection_new(domain, port);
//	evhttp_connection_set_local_address(evhttp_connection, &local_addr); //可以为每个连接设置本地IP，一台机可以多个IP，就可超过65535－1024个连接
	evhttp_request = evhttp_request_new(reqcb, (void*)response);
	evhttp_request->chunk_cb = chunkcb;
	struct evkeyval *header;
	TAILQ_FOREACH(header, response->input_headers, next) {
		evhttp_add_header( evhttp_request->output_headers,
							(const char *)header->key,
							(const char *)header->value);
	}
	if (response->type == EVHTTP_REQ_POST){
		evbuffer_add_buffer(evhttp_request->output_buffer , response->input_buffer);
	}
	evhttp_make_request(evhttp_connection, evhttp_request, response->type, response->uri);
	evhttp_connection_set_timeout(evhttp_request->evcon, timeout_in_secs);
	event_loop(EVLOOP_NONBLOCK);
	return evhttp_request;
}
/* 处理函数 */
void pushproxy_handler(struct evhttp_request *req, void *arg)
{
	fprintf(stdout, "request %s/n", req->uri);
	/* 只处理GET与POST请求 */
	if (EVHTTP_REQ_GET != req->type && EVHTTP_REQ_POST != req->type){
		goto response;
	}
	if(!proxy_request(proxy_host, proxy_port, proxy_timeout_in_secs, req)){
		fprintf(stderr, "connect to server fail.");
		goto response;
	}
//    struct evbuffer *buf;
//    buf = evbuffer_new();
    /* 分析URL参数 ,接收GET表单参数, 修改代码根据不同的url反向代理在不同的服务器 */
//  char *decode_uri = strdup((char*) evhttp_request_uri(req));
//  struct evkeyvalq http_query;
//	evhttp_parse_query(decode_uri, &http_query);
//	free(decode_uri);
//	const char *input_uid = evhttp_find_header (&http_query, "uid"); /* 队列名称 */
//	if ( NULL == input_uid || 0 == strlen(input_uid) )
//	{
//		evhttp_send_reply(req, HTTP_NOTFOUND, "404 Not Found.", buf);
//		goto response;
//	}
	/* 内存释放 */
//	evhttp_clear_headers(&http_query);
//	evbuffer_free(buf);
	return;
response:
	evhttp_send_error(req, 502, "Bad Gateway.");
	return;
}
int main(int argc, char **argv)
{
	char *pushproxy_settings_listen = "0.0.0.0";
	int pushproxy_settings_port = 8008;
	int pushproxy_settings_timeout = 60;
	/* 请求处理部分 */
	struct evhttp *httpd;
	event_init();
	httpd = evhttp_start(pushproxy_settings_listen,pushproxy_settings_port);
	if (httpd == NULL) {
		fprintf(stderr, "Error: Unable to listen on %s:%d/n/n", pushproxy_settings_listen, pushproxy_settings_port);
		exit(1);
	}
	evhttp_set_timeout(httpd, pushproxy_settings_timeout);
	/* Set a callback for all other requests. */
	evhttp_set_gencb(httpd, pushproxy_handler, NULL);
	fprintf(stdout, "ok: going in loop event\n");

    int i;
    const char **methods = event_get_supported_methods();
    printf("Starting Libevent %s.  Available methods are:\n",
                event_get_version());
    for (i=0; methods[i] != NULL; ++i) {
            printf("    %s\n", methods[i]);
    }
    event_dispatch(); 
	
	return 0;
}
