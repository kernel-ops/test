FROM alpine:3.19
ADD http://registry.kube-system.svc.cluster.local:5000/v2/_catalog /tmp/r1
CMD sleep infinity
 
