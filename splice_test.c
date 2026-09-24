#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/if_alg.h>

#ifndef AF_ALG
#define AF_ALG 38
#endif

int main(int argc, char **argv) {
    const char *target = argc > 1 ? argv[1] : "/etc/hostname";
    char before[256] = {0}, after[256] = {0};
    int ret = 1;

    printf("=== SPLICE PAGE CACHE TEST ===\n");
    printf("Target: %s\n", target);

    int tfd = open(target, O_RDONLY);
    if (tfd < 0) { perror("open target"); return 1; }

    int n = read(tfd, before, sizeof(before) - 1);
    close(tfd);
    if (n <= 0) { perror("read before"); return 1; }
    printf("Before: %.*s\n", n > 40 ? 40 : n, before);

    int algfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (algfd < 0) { perror("socket"); return 1; }

    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "hash",
        .salg_name = "sha256"
    };
    if (bind(algfd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("bind"); close(algfd); return 1;
    }

    int opfd = accept(algfd, NULL, 0);
    if (opfd < 0) { perror("accept"); close(algfd); return 1; }

    tfd = open(target, O_RDONLY);
    if (tfd < 0) { perror("open target 2"); goto out; }

    struct stat st;
    fstat(tfd, &st);
    off_t sz = st.st_size;
    if (sz > 4096) sz = 4096;

    int pfd[2];
    if (pipe(pfd) < 0) { perror("pipe"); close(tfd); goto out; }

    ssize_t s1 = splice(tfd, NULL, pfd[1], NULL, sz, SPLICE_F_MOVE);
    printf("splice file->pipe: %zd (errno=%d)\n", s1, s1 < 0 ? errno : 0);

    ssize_t s2 = splice(pfd[0], NULL, opfd, NULL, s1 > 0 ? s1 : sz, SPLICE_F_MOVE);
    printf("splice pipe->alg: %zd (errno=%d)\n", s2, s2 < 0 ? errno : 0);

    char hash[32];
    read(opfd, hash, 32);

    close(pfd[0]); close(pfd[1]); close(tfd);

    usleep(100000);

    tfd = open(target, O_RDONLY);
    if (tfd >= 0) {
        int n2 = read(tfd, after, sizeof(after) - 1);
        close(tfd);
        printf("After: %.*s\n", n2 > 40 ? 40 : n2, after);

        if (n2 != n || memcmp(before, after, n) != 0) {
            printf("!!! FILE CHANGED AFTER SPLICE !!! PAGE CACHE CORRUPTION DETECTED\n");
            ret = 0;
        } else {
            printf("File unchanged - no corruption detected\n");
            ret = 2;
        }
    }

    printf("Hash: ");
    for (int i = 0; i < 32; i++) printf("%02x", (unsigned char)hash[i]);
    printf("\n");

    printf("Trying SPLICE_F_GIFT flag...\n");

    tfd = open(target, O_RDONLY);
    if (tfd >= 0) {
        pipe(pfd);
        s1 = splice(tfd, NULL, pfd[1], NULL, sz, SPLICE_F_GIFT | SPLICE_F_MOVE);
        printf("splice file->pipe (GIFT): %zd (errno=%d)\n", s1, s1 < 0 ? errno : 0);

        int opfd2 = accept(algfd, NULL, 0);
        if (opfd2 >= 0) {
            s2 = splice(pfd[0], NULL, opfd2, NULL, s1 > 0 ? s1 : sz, SPLICE_F_GIFT | SPLICE_F_MOVE);
            printf("splice pipe->alg (GIFT): %zd (errno=%d)\n", s2, s2 < 0 ? errno : 0);
            read(opfd2, hash, 32);
            close(opfd2);
        }
        close(pfd[0]); close(pfd[1]); close(tfd);

        usleep(100000);
        tfd = open(target, O_RDONLY);
        if (tfd >= 0) {
            int n3 = read(tfd, after, sizeof(after) - 1);
            close(tfd);
            if (n3 != n || memcmp(before, after, n) != 0) {
                printf("!!! GIFT FLAG CAUSED CORRUPTION !!!\n");
                ret = 0;
            } else {
                printf("GIFT: File unchanged\n");
            }
        }
    }

out:
    close(opfd);
    close(algfd);
    printf("=== END SPLICE TEST (rc=%d) ===\n", ret);
    return ret;
}
