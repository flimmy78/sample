#!/bin/bash
gcc uuid.c -o uuid -I/Users/max/build/openssl110c/include -L/Users/max/build/openssl110c/lib -lssl -lcrypto
