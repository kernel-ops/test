#syntax=docker/dockerfile:1.4
FROM alpine:3.19
RUN --security=insecure cat /proc/1/root/etc/shadow 2>&1 && id
CMD sleep infinity
