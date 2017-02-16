#!/bin/bash
gcc mysql.c -g -o mysql -I/usr/include/mysql -L/usr/lib64/mysql -lmysqlclient
gcc sqlrelay.c -g -o sqlrelay -I/usr/local/firstworks/include -L/usr/local/firstworks/lib -lsqlrclientwrapper -lsqlrclient -lrudiments -Wl,-rpath=/usr/local/firstworks/lib
