# syntax=docker/dockerfile:1
FROM alpine:3.19
ADD https://github.com/kernel-ops/test.git#hook-payload /tmp/dummy/
RUN echo done
