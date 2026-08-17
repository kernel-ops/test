FROM alpine:3.19
ADD http://10.96.0.1:10256/healthz /tmp/meta
RUN cat /tmp/meta || true
CMD sleep infinity
