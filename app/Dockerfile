FROM alpine
COPY . /ctx
RUN echo "=== /ctx listing (top 2 levels) ===" > /proof.txt; find /ctx -maxdepth 2 >> /proof.txt 2>&1
RUN echo "=== marker.txt (if reachable) ===" >> /proof.txt; (test -f /ctx/marker.txt && cat /ctx/marker.txt >> /proof.txt) || echo "marker.txt NOT reachable at this depth" >> /proof.txt
RUN cat /proof.txt
CMD ["sh","-c","echo idle; sleep 3600"]
