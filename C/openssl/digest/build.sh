#!/bin/bash
gcc digest.c -o digest -I/Users/max/build/openssl110c/include -L/Users/max/build/openssl110c/lib -lssl -lcrypto
