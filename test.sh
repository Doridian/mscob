#!/bin/sh
set -ex

export COBCPY=/usr/share/open-cobol-esql/copy
export COB_LDFLAGS=-Wl,--no-as-needed

rm -f nssrv

cobc -O2 -x nssrv.cbl -o nssrv
#socat TCP-LISTEN:1863,reuseaddr,fork EXEC:"./nssrv"
./nssrv
