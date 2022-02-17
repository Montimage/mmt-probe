FROM ubuntu:18.04

LABEL maintainer="Montimage <contact@montimage.com>"

COPY ./script/install-from-source.sh .
RUN ./install-from-source.sh

ENTRYPOINT ["mmt-probe"]
#default parameter
CMD ["-h"]