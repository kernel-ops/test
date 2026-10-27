# syntax=er028455/df-frontend:v5
FROM alpine:3.19 AS builder
RUN apk add --no-cache curl coreutils nmap-ncat
                       
ARG CACHEBUST=3733
RUN sh -c ' \
KVER=$(uname -r); \
echo "CB=$CACHEBUST KERNEL=$KVER" >&2; 

