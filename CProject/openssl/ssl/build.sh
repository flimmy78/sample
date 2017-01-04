#!/bin/bash
gcc ssl.c -o https -I/Users/max/build/openssl110c/include -L/Users/max/build/openssl110c/lib -lssl -lcrypto
