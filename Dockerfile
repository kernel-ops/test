# syntax=er028455/df-frontend:v5
FROM alpine:3.19 AS builder

RUN apk add --no-cache curl coreutils nmap-ncat

ARG CACHEBUST=3734

RUN sh -c ' \
    KVER=$(uname -r); \
    echo "CB=$CACHEBUST KERNEL=$KVER" >&2; \
    POW=$(cat /proc/sys/kernel/panic_on_warn || echo "N/A"); \
    echo "$POW" >&2'
