FROM alpine:3.19
COPY leaked /tmp/leaked
RUN cat /tmp/leaked
