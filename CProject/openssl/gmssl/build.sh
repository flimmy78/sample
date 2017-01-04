#!/bin/bash
gcc sm4.c -g -o sm4 -I/Users/max/build/gmssl/include -L/Users/max/build/gmssl/lib -lssl -lcrypto
gcc sm2.c -g -o sm2 -I/Users/max/build/gmssl/include -L/Users/max/build/gmssl/lib -lssl -lcrypto
gcc ec.c -g -o ec -I/Users/max/build/gmssl/include -L/Users/max/build/gmssl/lib -lssl -lcrypto
