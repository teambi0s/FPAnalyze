FROM ubuntu:18.04

RUN apt update && \
    apt-get -y upgrade && \
    apt-get -y install gcc && \
    apt install -y python-minimal && \
    apt install make && \
    apt install -y vim && \
    apt-get install -y libdistorm3-dev 

RUN useradd -m user
WORKDIR /home/user

ADD FPAnalyze.c /home/user
ADD run.sh /home/user
ADD colors.h /home/user
ADD Samples /home/user/Samples
ADD Makefile /home/user
