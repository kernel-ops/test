FROM alpine:3.19
ADD http://127.0.0.1:2379/version /tmp/etcd
CMD sleep infinity
