FROM alpine
COPY leak /proof.txt
RUN echo "=== leak (absolute symlink /etc/hostname), isolated test ===" > /result.txt; (cat /proof.txt >> /result.txt 2>&1) || echo "leak not readable" >> /result.txt
RUN cat /result.txt
CMD ["sh","-c","echo idle; sleep 3600"]
