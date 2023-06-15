FROM ubuntu:20.04

LABEL maintainer="Montimage <contact@montimage.com>"

ARG MMT_PROBE_VERSION=master
ARG MMT_DPI_VERSION=master
ARG MMT_SECURITY_VERSION=main

ENV DEBIAN_FRONTEND=noninteractive

COPY ./script/install-from-source.sh .
RUN ./install-from-source.sh

ENTRYPOINT ["mmt-probe"]
#default parameter
CMD ["-h"]