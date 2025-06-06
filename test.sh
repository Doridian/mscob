#!/bin/sh
set -ex

export COBCPY=/usr/share/open-cobol-esql/copy
export COB_LDFLAGS=-Wl,--no-as-needed

rm -f notification-server switchboard-server


cobc -O2 -lcrypto -x notification-server.cbl files.c -o notification-server
#socat TCP-LISTEN:1863,reuseaddr,fork EXEC:"./notification-server"
stty cbreak
./notification-server
