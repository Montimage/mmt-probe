#!/bin/bash

cp mosaico.conf mmt-probe.conf
make clean
make SOCKET_MODULE REDIS_MODULE compile
make SOCKET_MODULE REDIS_MODULE deb

# to test using docker ==> use ubuntu 22.10
# docker run --rm -it -v$PWD:/tmp/a ubuntu:22.10