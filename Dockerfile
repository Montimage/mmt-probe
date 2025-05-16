FROM ubuntu:22.04

LABEL maintainer="Montimage <contact@montimage.com>"

COPY . .
RUN ./script/install-from-source.sh

ENTRYPOINT ["mmt-probe"]
#default parameter
CMD ["-h"]