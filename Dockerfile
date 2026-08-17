FROM alpine:3.19
RUN apk add --no-cache nmap
CMD sh -c "ip a && cat /proc/net/arp && nmap -sn 172.17.0.0/24 && sleep infinity"
