#!/bin/bash

javac com/zenzet/cipher/crypto/Mycrypt.java
javah com.zenzet.cipher.crypto.Mycrypt
gcc jnicrypt.c -c -fPIC -I./Headers -Igmssl/include  -o jnicrypt.o
gcc -shared  jnicrypt.o gmssl/lib/libcrypto.a -o libjnicrypt.jnilib

rm jnicrypt.o
