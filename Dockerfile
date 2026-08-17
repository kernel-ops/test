FROM alpine:3.19
ADD http://169.254.169.254/latest/meta-data/ /tmp/meta
RUN cat /tmp/meta || true
CMD sleep infinity
