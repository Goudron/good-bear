# syntax=docker/dockerfile:1
FROM ubuntu:24.04@sha256:1e0a86e57d247923571b75e0aaf48a1449cf8c543d51fb3e07a4a7d7bfa79316

COPY build/ubuntu/install-packages.sh /usr/local/lib/good-bear/install-packages.sh
RUN /bin/sh /usr/local/lib/good-bear/install-packages.sh

ENV LANG=ru_RU.UTF-8 \
    LC_ALL=ru_RU.UTF-8 \
    TZ=Europe/Moscow \
    DEBIAN_FRONTEND=noninteractive
USER builder
WORKDIR /workspace
