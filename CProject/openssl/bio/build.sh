#!/bin/bash
gcc md5_bio.c -o md5_bio -I/Users/max/build/openssl110c/include -L/Users/max/build/openssl110c/lib -lssl -lcrypto
