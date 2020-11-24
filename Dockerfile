FROM ubuntu:latest

RUN apt-get update -y -q && apt-get upgrade -y -q && apt-get -y install sudo
RUN DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y -q curl build-essential ca-certificates git
RUN curl -s https://storage.googleapis.com/golang/go1.9.linux-amd64.tar.gz| tar -v -C /usr/local -xz
ENV PATH $PATH:/usr/local/go/bin
ENV GOOS linux
ENV GOARCH amd64
WORKDIR /go

RUN useradd -m docker && echo "docker:docker" | chpasswd && adduser docker sudo
USER docker
