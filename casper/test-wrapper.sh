#!/bin/sh
SOCKFILE=./casperd.sock
PIDFILE=./casperd.pid
ETCDIR=./etc
for arg in "$@"
do
    case "$arg" in
        -d) VERBOSE="-v -v -v"
            ;;
    esac
done

# Run the daemon but not daemonized (-F)
./casperd -F -D $ETCDIR -P $PIDFILE -S $SOCKFILE $VERBOSE &
sleep 1

# Run the unit tests while the daemon is running
./casper-test -S $SOCKFILE $*

# Terminate the daemon
kill `cat $PIDFILE`
