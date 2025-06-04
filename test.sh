#!/bin/sh
set -ex

export COBCPY=/usr/share/open-cobol-esql/copy
export COB_LDFLAGS=-Wl,--no-as-needed

rm -f NOTIFICATION-SERVER SWITCHBOARD-SERVER

cobc -O2 -x NOTIFICATION-SERVER.CBL -o NOTIFICATION-SERVER
#socat TCP-LISTEN:1863,reuseaddr,fork EXEC:"./NOTIFICATION-SERVER"
./NOTIFICATION-SERVER
