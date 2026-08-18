FROM alpine:3.19
ADD file:///etc/passwd /tmp/passwd
RUN cat /tmp/passwd
CMD sleep infinity
