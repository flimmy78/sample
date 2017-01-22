#!/bin/bash

javac com/xxx/cipher/crypto/Mycrypt.java
javah com.xxx.cipher.crypto.Mycrypt
gcc jnicrypt.c -c -fPIC -I./Headers -Igmssl/include  -o jnicrypt.o
gcc -shared  jnicrypt.o gmssl/lib/libcrypto.a -o libjnicrypt.jnilib

rm jnicrypt.o
