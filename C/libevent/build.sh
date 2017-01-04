#!/bin/bash
#gcc main.c -I./install/include -L./install/lib install/lib/libevent.a -o main
gcc tmp.c -g -I./install/include -L./install/lib install/lib/libevent.a -o tmp
#gcc proxy.c -g -I./install/include -L./install/lib install/lib/libevent.a -o proxy
#gcc bfevent_httpclient.c -g -I./install/include -L./install/lib install/lib/libevent.a -o bfevent_httpclient
gcc http-server.c -g -I./install/include  -I./zlib/include -L./install/lib -L./zlib/lib install/lib/libevent.a zlib/lib/libz.a -o http-server
