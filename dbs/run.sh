#!/bin/bash
VERSION=1.0.2
LOCKET=/home/max/LOCKet
ACCESS_DIR=$LOCKET/lss-dbs-access/target/lss-dbs-access-$VERSION
CORE_DIR=$LOCKET/lss-dbs-core/target/lss-dbs-core-$VERSION
WEB_DIR=$LOCKET/lss-dbs-web/

ACTION=$1

start (){
    cd $ACCESS_DIR
    ./startServer.sh $ACTION

    cd $CORE_DIR
    ./startServer.sh $ACTION

    cd $WEB_DIR
    NODE_ENV=dev pm2 start lss-dbs-web.js
}

status ()
{
    ps -aux | grep -P "lss-dbs-core|lss-dbs-web|lss-dbs-access" | grep -v grep
}

stop ()
{
    cd $ACCESS_DIR
    ./startServer.sh $ACTION

    cd $CORE_DIR
    ./startServer.sh $ACTION

    cd $WEB_DIR
    NODE_ENV=dev pm2 stop lss-dbs-web.js
}

usage () {
    echo "Usage: $0 status|start|stop|restart"
    exit 1
}

if [ $# -lt 1 ]
then
    usage
fi


if [ "$1" == "status" ]
then
    status
elif [ "$1" == "start" ]
then
    start
elif [ "$1" == "stop" ]
then
    stop
elif [ "$1" == "restart" ]
then
    stop
    start
else
    usage
fi
