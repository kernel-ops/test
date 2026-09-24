#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <fcntl.h>

#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

struct test_alg {
    const char *type;
    const char *name;
};

static struct test_alg algs[] = {
    {"hash", "sha256"},
    {"hash", "sha1"},
    {"hash", "md5"},
    {"hash", "sha512"},
    {"skcipher", "cbc(aes)"},
    {"skcipher", "ecb(aes)"},
    {"skcipher", "xts(aes)"},
    {"skcipher", "ctr(aes)"},
    {"aead", "gcm(aes)"},
    {"aead", "ccm(aes)"},
    {"aead", "authenc(hmac(sha256),cbc(aes))"},
    {"aead", "authencesn(hmac(sha256),cbc(aes))"},
    {"rng", "drbg_nopr_sha256"},
    {"rng", "drbg_nopr_hmac_sha256"},
};

int test_splice(int opfd) {
    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;

    char data[] = "AAAAAAAAAAAAAAAA";
    write(pipefd[1], data, sizeof(data));

    ssize_t r = splice(pipefd[0], NULL, opfd, NULL, sizeof(data), 0);
    int e = errno;
    close(pipefd[0]);
    close(pipefd[1]);
    if (r < 0) {
        printf("  splice: FAILED errno=%d (%s)\n", e, strerror(e));
        return -1;
    }
    printf("  splice: OK (%zd bytes)\n", r);
    return 0;
}

int main(void) {
    int n = sizeof(algs) / sizeof(algs[0]);

    printf("=== AF_ALG ALGORITHM TEST ===\n");

    for (int i = 0; i < n; i++) {
        int fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
        if (fd < 0) {
            printf("[%s/%s] socket: FAILED errno=%d\n", algs[i].type, algs[i].name, errno);
            continue;
        }

        struct sockaddr_alg sa;
        memset(&sa, 0, sizeof(sa));
        sa.salg_family = AF_ALG;
        strncpy((char*)sa.salg_type, algs[i].type, sizeof(sa.salg_type) - 1);
        strncpy((char*)sa.salg_name, algs[i].name, sizeof(sa.salg_name) - 1);

        int r = bind(fd, (struct sockaddr*)&sa, sizeof(sa));
        if (r < 0) {
            printf("[%s/%s] bind: FAILED errno=%d (%s)\n", algs[i].type, algs[i].name, errno, strerror(errno));
            close(fd);
            continue;
        }

        printf("[%s/%s] bind: OK\n", algs[i].type, algs[i].name);

        if (strcmp(algs[i].type, "hash") == 0) {
            int opfd = accept(fd, NULL, 0);
            if (opfd >= 0) {
                printf("  accept: OK fd=%d\n", opfd);
                test_splice(opfd);

                char buf[] = "test data for hashing";
                ssize_t w = write(opfd, buf, sizeof(buf));
                printf("  write: %zd bytes (errno=%d)\n", w, w < 0 ? errno : 0);

                char hash[64];
                ssize_t rd = read(opfd, hash, sizeof(hash));
                printf("  read hash: %zd bytes\n", rd);

                close(opfd);
            } else {
                printf("  accept: FAILED errno=%d\n", errno);
            }
        } else if (strcmp(algs[i].type, "skcipher") == 0) {
            unsigned char key[16] = {0};
            setsockopt(fd, SOL_ALG, ALG_SET_KEY, key, 16);
            int opfd = accept(fd, NULL, 0);
            if (opfd >= 0) {
                printf("  accept+key: OK fd=%d\n", opfd);
                test_splice(opfd);
                close(opfd);
            } else {
                printf("  accept: FAILED errno=%d\n", errno);
            }
        } else if (strcmp(algs[i].type, "aead") == 0) {
            unsigned char key[20] = {0};
            setsockopt(fd, SOL_ALG, ALG_SET_KEY, key, 20);
            int opfd = accept(fd, NULL, 0);
            if (opfd >= 0) {
                printf("  accept+key: OK fd=%d\n", opfd);
                test_splice(opfd);
                close(opfd);
            } else {
                printf("  accept: FAILED errno=%d (%s)\n", errno, strerror(errno));
            }
        }

        close(fd);
    }

    printf("=== END ALG TEST ===\n");
    return 0;
}
