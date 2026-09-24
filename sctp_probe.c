#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#ifndef SCTP_ASCONF_SUPPORTED
#define SCTP_ASCONF_SUPPORTED 128
#endif
#ifndef SCTP_AUTH_SUPPORTED
#define SCTP_AUTH_SUPPORTED 129
#endif

#ifndef PACKET_VERSION
#define PACKET_VERSION 10
#endif
#ifndef PACKET_TX_RING
#define PACKET_TX_RING 13
#endif
#define TPACKET_V1 0

static void read_sysctl(const char *path) {
    char buf[256] = {0};
    int fd = open(path, O_RDONLY);
    if (fd < 0) { printf("  %s: FAILED (%s)\n", path, strerror(errno)); return; }
    int n = read(fd, buf, sizeof(buf)-1);
    close(fd);
    if (n > 0) { buf[n] = 0; char *nl = strchr(buf, '\n'); if (nl) *nl = 0; }
    printf("  %s: %s\n", path, n > 0 ? buf : "(empty)");
}

static void write_sysctl(const char *path, const char *val) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) { printf("  WRITE %s: FAILED open (%s)\n", path, strerror(errno)); return; }
    int r = write(fd, val, strlen(val));
    close(fd);
    printf("  WRITE %s=%s: %s\n", path, val, r > 0 ? "OK" : strerror(errno));
}

int main(void) {
    printf("=== SCTPHANTOM PREREQ PROBE ===\n");

    printf("--- KERNEL ---\n");
    char uname_buf[256];
    FILE *f = popen("uname -r", "r");
    if (f) { fgets(uname_buf, sizeof(uname_buf), f); pclose(f); printf("  kernel: %s", uname_buf); }

    printf("--- SCTP SOCKET ---\n");
    int sctp_stream = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    printf("  SCTP SOCK_STREAM: %s (fd=%d, errno=%d)\n", sctp_stream >= 0 ? "OK" : "FAIL", sctp_stream, sctp_stream < 0 ? errno : 0);
    int sctp_dgram = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
    printf("  SCTP SOCK_SEQPACKET: %s (fd=%d, errno=%d)\n", sctp_dgram >= 0 ? "OK" : "FAIL", sctp_dgram, sctp_dgram < 0 ? errno : 0);

    printf("--- AF_PACKET ---\n");
    int pkt = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
    printf("  AF_PACKET SOCK_DGRAM: %s (fd=%d, errno=%d %s)\n",
           pkt >= 0 ? "OK" : "FAIL", pkt, pkt < 0 ? errno : 0, pkt < 0 ? strerror(errno) : "");
    if (pkt >= 0) {
        int v = TPACKET_V1;
        int sv = setsockopt(pkt, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
        printf("  PACKET_VERSION=V1: %s (errno=%d)\n", sv == 0 ? "OK" : "FAIL", sv < 0 ? errno : 0);
        struct { unsigned int bs, bn, fs, fn; } req = {4096, 4, 512, 32};
        int tr = setsockopt(pkt, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));
        printf("  PACKET_TX_RING: %s (errno=%d %s)\n", tr == 0 ? "OK" : "FAIL", tr < 0 ? errno : 0, tr < 0 ? strerror(errno) : "");
        if (tr == 0) {
            void *m = mmap(0, 4096*4, PROT_READ|PROT_WRITE, MAP_SHARED, pkt, 0);
            printf("  TX_RING mmap: %s\n", m != MAP_FAILED ? "OK" : "FAIL");
            if (m != MAP_FAILED) munmap(m, 4096*4);
        }
        close(pkt);
    }

    printf("--- RAW SOCKET ---\n");
    int raw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    printf("  SOCK_RAW IPPROTO_RAW: %s (fd=%d, errno=%d %s)\n",
           raw >= 0 ? "OK" : "FAIL", raw, raw < 0 ? errno : 0, raw < 0 ? strerror(errno) : "");
    if (raw >= 0) {
        int one = 1;
        int hi = setsockopt(raw, IPPROTO_IP, 3 /*IP_HDRINCL*/, &one, sizeof(one));
        printf("  IP_HDRINCL: %s\n", hi == 0 ? "OK" : "FAIL");
        close(raw);
    }
    int raw_sctp = socket(AF_INET, SOCK_RAW, IPPROTO_SCTP);
    printf("  SOCK_RAW IPPROTO_SCTP: %s (errno=%d %s)\n",
           raw_sctp >= 0 ? "OK" : "FAIL", raw_sctp < 0 ? errno : 0, raw_sctp < 0 ? strerror(errno) : "");
    if (raw_sctp >= 0) close(raw_sctp);

    printf("--- SCTP SYSCTL ---\n");
    read_sysctl("/proc/sys/net/sctp/addip_enable");
    read_sysctl("/proc/sys/net/sctp/addip_noauth_enable");
    read_sysctl("/proc/sys/net/sctp/auth_enable");
    read_sysctl("/proc/sys/net/sctp/hb_interval");
    write_sysctl("/proc/sys/net/sctp/addip_enable", "1");

    printf("--- SCTP PER-SOCKET OPTIONS ---\n");
    if (sctp_stream >= 0) {
        int val = 1;
        int r1 = setsockopt(sctp_stream, IPPROTO_SCTP, SCTP_AUTH_SUPPORTED, &val, sizeof(val));
        printf("  SCTP_AUTH_SUPPORTED: %s (errno=%d %s)\n", r1 == 0 ? "OK" : "FAIL", r1 < 0 ? errno : 0, r1 < 0 ? strerror(errno) : "");
        int r2 = setsockopt(sctp_stream, IPPROTO_SCTP, SCTP_ASCONF_SUPPORTED, &val, sizeof(val));
        printf("  SCTP_ASCONF_SUPPORTED: %s (errno=%d %s)\n", r2 == 0 ? "OK" : "FAIL", r2 < 0 ? errno : 0, r2 < 0 ? strerror(errno) : "");
    }

    printf("--- SYSV IPC ---\n");
    int q = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
    printf("  msgget: %s (id=%d, errno=%d %s)\n", q >= 0 ? "OK" : "FAIL", q, q < 0 ? errno : 0, q < 0 ? strerror(errno) : "");
    if (q >= 0) {
        struct { long mtype; char mtext[64]; } mb;
        mb.mtype = 1; memset(mb.mtext, 'A', 64);
        int ms = msgsnd(q, &mb, 64, IPC_NOWAIT);
        printf("  msgsnd: %s (errno=%d)\n", ms == 0 ? "OK" : "FAIL", ms < 0 ? errno : 0);
        msgctl(q, IPC_RMID, NULL);
    }

    printf("--- UNSHARE ---\n");
    int us = unshare(CLONE_NEWUSER | CLONE_NEWNET);
    printf("  CLONE_NEWUSER|NEWNET: %s (errno=%d %s)\n", us == 0 ? "OK" : "FAIL", us < 0 ? errno : 0, us < 0 ? strerror(errno) : "");
    if (us < 0) {
        us = unshare(CLONE_NEWNET);
        printf("  CLONE_NEWNET only: %s (errno=%d %s)\n", us == 0 ? "OK" : "FAIL", us < 0 ? errno : 0, us < 0 ? strerror(errno) : "");
    }

    printf("--- LOOPBACK ---\n");
    int lo = socket(AF_INET, SOCK_DGRAM, 0);
    if (lo >= 0) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, "lo");
        if (ioctl(lo, SIOCGIFFLAGS, &ifr) == 0)
            printf("  lo flags: 0x%x (UP=%d RUNNING=%d)\n", ifr.ifr_flags, !!(ifr.ifr_flags & IFF_UP), !!(ifr.ifr_flags & IFF_RUNNING));
        else
            printf("  lo ioctl: FAILED (%s)\n", strerror(errno));

        struct sockaddr_in bind_lo;
        memset(&bind_lo, 0, sizeof(bind_lo));
        bind_lo.sin_family = AF_INET;
        bind_lo.sin_port = htons(31337);
        bind_lo.sin_addr.s_addr = htonl(0x7f000001);
        int br = bind(lo, (struct sockaddr*)&bind_lo, sizeof(bind_lo));
        printf("  bind 127.0.0.1:31337: %s (errno=%d)\n", br == 0 ? "OK" : "FAIL", br < 0 ? errno : 0);
        close(lo);
    }

    printf("--- BTF ---\n");
    int btf = open("/sys/kernel/btf/vmlinux", O_RDONLY);
    if (btf >= 0) {
        off_t sz = lseek(btf, 0, SEEK_END);
        printf("  /sys/kernel/btf/vmlinux: OK (%ld bytes)\n", (long)sz);
        close(btf);
    } else {
        printf("  /sys/kernel/btf/vmlinux: FAILED (%s)\n", strerror(errno));
    }

    printf("--- KALLSYMS OFFSETS ---\n");
    FILE *ks = fopen("/proc/kallsyms", "r");
    if (ks) {
        char line[256];
        int found = 0;
        while (fgets(line, sizeof(line), ks)) {
            if (strstr(line, " commit_creds") ||
                strstr(line, " prepare_kernel_cred") ||
                strstr(line, " init_user_ns") ||
                strstr(line, " init_cred") ||
                strstr(line, "__per_cpu_offset") ||
                strstr(line, " current_task") ||
                strstr(line, "sctp_sf_do_asconf")) {
                printf("  %s", line);
                found++;
            }
        }
        fclose(ks);
        if (!found) printf("  (all zeroed or empty)\n");
    } else {
        printf("  /proc/kallsyms: FAILED (%s)\n", strerror(errno));
    }

    printf("--- IDT BASE (SIDT) ---\n");
    unsigned char idt_buf[10];
    asm volatile("sidt %0" : "=m"(idt_buf));
    uint64_t idt_base = 0;
    for (int i = 0; i < 8; i++) idt_base |= (uint64_t)idt_buf[2+i] << (8*i);
    printf("  IDT base: 0x%016lx\n", (unsigned long)idt_base);

    printf("--- SCTP PROC ---\n");
    const char *sctp_procs[] = {"/proc/net/sctp/assocs", "/proc/net/sctp/eps",
                                "/proc/net/sctp/remaddr", "/proc/net/sctp/snmp", NULL};
    for (int i = 0; sctp_procs[i]; i++) {
        int sfd = open(sctp_procs[i], O_RDONLY);
        printf("  %s: %s\n", sctp_procs[i], sfd >= 0 ? "OK" : strerror(errno));
        if (sfd >= 0) close(sfd);
    }

    printf("--- CAPABILITIES ---\n");
    char cap_buf[256];
    int cfd = open("/proc/self/status", O_RDONLY);
    if (cfd >= 0) {
        int n = read(cfd, cap_buf, sizeof(cap_buf)-1);
        close(cfd);
        if (n > 0) {
            cap_buf[n] = 0;
            char *p = cap_buf;
            while ((p = strstr(p, "Cap"))) {
                char *nl = strchr(p, '\n');
                if (nl) { *nl = 0; printf("  %s\n", p); *nl = '\n'; p = nl+1; }
                else { printf("  %s\n", p); break; }
            }
        }
    }

    if (sctp_stream >= 0) close(sctp_stream);
    if (sctp_dgram >= 0) close(sctp_dgram);

    printf("=== END SCTPHANTOM PROBE ===\n");
    return 0;
}
