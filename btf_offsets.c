#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define BTF_MAGIC 0xEB9F
#define BTF_KIND_INT       1
#define BTF_KIND_PTR       2
#define BTF_KIND_ARRAY     3
#define BTF_KIND_STRUCT    4
#define BTF_KIND_UNION     5
#define BTF_KIND_ENUM      6
#define BTF_KIND_FWD       7
#define BTF_KIND_TYPEDEF   8
#define BTF_KIND_VOLATILE  9
#define BTF_KIND_CONST    10
#define BTF_KIND_RESTRICT 11

struct btf_header {
    uint16_t magic;
    uint8_t  version;
    uint8_t  flags;
    uint32_t hdr_len;
    uint32_t type_off;
    uint32_t type_len;
    uint32_t str_off;
    uint32_t str_len;
};

struct btf_type {
    uint32_t name_off;
    uint32_t info;
    union {
        uint32_t size;
        uint32_t type;
    };
};

struct btf_member {
    uint32_t name_off;
    uint32_t type;
    uint32_t offset;
};

#define BTF_INFO_KIND(i) (((i)>>24)&0x1f)
#define BTF_INFO_VLEN(i) ((i)&0xffff)
#define BTF_INFO_KFLAG(i) ((i)>>31)

struct query {
    const char *struct_name;
    const char *members[32];
    int nmembers;
};

static struct query queries[] = {
    {"sctp_transport", {"af_specific","asoc","cwnd","srtt","burst_limited","dst","pathmtu","param_flags","last_time_sent","state","send_ready",NULL}, 0},
    {"sctp_association", {"base","pmtu_pending","pathmtu","param_flags","state",NULL}, 0},
    {"sctp_af", {"net_header_len","get_dst","get_saddr","sockaddr_len",NULL}, 0},
    {"cred", {"usage","cap_permitted","cap_effective","cap_bset","user","user_ns","ucounts","group_info","security",NULL}, 0},
    {"task_struct", {"cred","real_cred","comm","pid","files","nsproxy","fs",NULL}, 0},
    {"files_struct", {"fdt","fd_array",NULL}, 0},
    {"fdtable", {"fd","max_fds",NULL}, 0},
    {"file", {"f_op","private_data","f_count",NULL}, 0},
    {"socket", {"sk","type","ops",NULL}, 0},
    {"sctp_sock", {"ep","auto_asconf_splist",NULL}, 0},
    {"sctp_endpoint", {"asocs","base",NULL}, 0},
    {"subprocess_info", {"work","complete","path","argv","envp","retval","init","cleanup","data",NULL}, 0},
    {"sctp_pf", {"af","to_sk_saddr",NULL}, 0},
    {"sctp_packet", {"vtag","chunk_list","overhead","size","transport","auth","has_cookie_echo",NULL}, 0},
    {"sock", {"__sk_common","sk_prot",NULL}, 0},
    {"pcpu_hot", {"current_task",NULL}, 0},
    {"sctp_ep_common", {"sk","bind_addr","state",NULL}, 0},
    {"inet_sock", {"sk",NULL}, 0},
    {"work_struct", {"data","entry","func",NULL}, 0},
    {NULL, {NULL}, 0}
};

static uint8_t *btf_data;
static size_t btf_size;
static struct btf_header *hdr;
static uint8_t *type_sec;
static char *str_sec;

static const char *btf_str(uint32_t off) {
    if (off >= hdr->str_len) return "";
    return str_sec + off;
}

static void find_struct_offsets(const char *name, const char **members) {
    uint8_t *p = type_sec;
    uint8_t *end = type_sec + hdr->type_len;
    uint32_t tid = 1;

    while (p < end) {
        struct btf_type *t = (struct btf_type *)p;
        uint32_t kind = BTF_INFO_KIND(t->info);
        uint32_t vlen = BTF_INFO_VLEN(t->info);
        uint32_t kflag = BTF_INFO_KFLAG(t->info);

        p += sizeof(struct btf_type);

        if (kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION) {
            const char *sname = btf_str(t->name_off);
            if (strcmp(sname, name) == 0) {
                printf("--- %s (size=%u, members=%u) ---\n", name, t->size, vlen);
                struct btf_member *m = (struct btf_member *)p;
                for (uint32_t i = 0; i < vlen; i++) {
                    const char *mname = btf_str(m[i].name_off);
                    uint32_t bit_off = kflag ? (m[i].offset & 0xFFFFFF) : m[i].offset;
                    uint32_t byte_off = bit_off / 8;
                    uint32_t bit_rem = bit_off % 8;

                    for (int j = 0; members[j]; j++) {
                        if (strcmp(mname, members[j]) == 0) {
                            if (bit_rem)
                                printf("  %s: byte=%u bit=%u (0x%x)\n", mname, byte_off, bit_off, byte_off);
                            else
                                printf("  %s: %u (0x%x)\n", mname, byte_off, byte_off);
                        }
                    }
                }
                printf("  SIZEOF=%u\n", t->size);
                return;
            }
            p += vlen * sizeof(struct btf_member);
        } else if (kind == BTF_KIND_INT) {
            p += 4;
        } else if (kind == BTF_KIND_ARRAY) {
            p += 12;
        } else if (kind == BTF_KIND_ENUM) {
            p += vlen * 8;
        } else {
            /* PTR, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FUNC_PROTO,
               VAR, DATASEC, FLOAT, DECL_TAG, TYPE_TAG, ENUM64 */
            if (kind == 12) /* FUNC */
                ; /* no extra data */
            else if (kind == 13) /* FUNC_PROTO */
                p += vlen * 8;
            else if (kind == 14) /* VAR */
                p += 4;
            else if (kind == 15) /* DATASEC */
                p += vlen * 12;
            else if (kind == 16) /* FLOAT */
                ; /* no extra */
            else if (kind == 17) /* DECL_TAG */
                p += 4;
            else if (kind == 18) /* TYPE_TAG */
                ; /* no extra */
            else if (kind == 19) /* ENUM64 */
                p += vlen * 12;
            /* else: PTR(2), FWD(7), TYPEDEF(8), VOLATILE(9), CONST(10), RESTRICT(11) - no extra */
        }
        tid++;
    }
    printf("--- %s: NOT FOUND ---\n", name);
}

static void advance_type(uint8_t **pp, uint32_t kind, uint32_t vlen) {
    if (kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION)
        *pp += vlen * sizeof(struct btf_member);
    else if (kind == BTF_KIND_INT)
        *pp += 4;
    else if (kind == BTF_KIND_ARRAY)
        *pp += 12;
    else if (kind == BTF_KIND_ENUM)
        *pp += vlen * 8;
    else if (kind == 13) /* FUNC_PROTO */
        *pp += vlen * 8;
    else if (kind == 14) /* VAR */
        *pp += 4;
    else if (kind == 15) /* DATASEC */
        *pp += vlen * 12;
    else if (kind == 17) /* DECL_TAG */
        *pp += 4;
    else if (kind == 19) /* ENUM64 */
        *pp += vlen * 12;
}

static struct btf_type *find_type_by_id(uint32_t target_id) {
    if (target_id == 0) return NULL;
    uint8_t *p = type_sec;
    uint8_t *end = type_sec + hdr->type_len;
    uint32_t tid = 1;
    while (p < end && tid < target_id) {
        struct btf_type *t = (struct btf_type *)p;
        uint32_t kind = BTF_INFO_KIND(t->info);
        uint32_t vlen = BTF_INFO_VLEN(t->info);
        p += sizeof(struct btf_type);
        advance_type(&p, kind, vlen);
        tid++;
    }
    return (tid == target_id && p < end) ? (struct btf_type *)p : NULL;
}

static void dump_members_recursive(uint32_t type_id, uint32_t base_off, const char *prefix, int depth) {
    if (depth > 4) return;
    struct btf_type *t = find_type_by_id(type_id);
    if (!t) return;
    uint32_t kind = BTF_INFO_KIND(t->info);
    if (kind != BTF_KIND_STRUCT && kind != BTF_KIND_UNION) return;
    uint32_t vlen = BTF_INFO_VLEN(t->info);
    uint32_t kflag = BTF_INFO_KFLAG(t->info);
    struct btf_member *m = (struct btf_member *)((uint8_t*)t + sizeof(struct btf_type));
    for (uint32_t i = 0; i < vlen; i++) {
        const char *mname = btf_str(m[i].name_off);
        uint32_t bit_off = kflag ? (m[i].offset & 0xFFFFFF) : m[i].offset;
        uint32_t byte_off = base_off + bit_off / 8;
        if (mname[0] == '\0') {
            dump_members_recursive(m[i].type, byte_off, prefix, depth+1);
        } else {
            printf("  %s%s: %u (0x%x)\n", prefix, mname, byte_off, byte_off);
        }
    }
}

static void dump_all_members(const char *name) {
    uint8_t *p = type_sec;
    uint8_t *end = type_sec + hdr->type_len;
    uint32_t tid = 1;

    while (p < end) {
        struct btf_type *t = (struct btf_type *)p;
        uint32_t kind = BTF_INFO_KIND(t->info);
        uint32_t vlen = BTF_INFO_VLEN(t->info);
        uint32_t kflag = BTF_INFO_KFLAG(t->info);

        p += sizeof(struct btf_type);

        if (kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION) {
            const char *sname = btf_str(t->name_off);
            if (strcmp(sname, name) == 0) {
                printf("=== FULL DUMP: %s (size=%u) ===\n", name, t->size);
                struct btf_member *m = (struct btf_member *)p;
                for (uint32_t i = 0; i < vlen; i++) {
                    const char *mname = btf_str(m[i].name_off);
                    uint32_t bit_off = kflag ? (m[i].offset & 0xFFFFFF) : m[i].offset;
                    uint32_t byte_off = bit_off / 8;
                    uint32_t bit_rem = bit_off % 8;
                    if (bit_rem)
                        printf("  [%3u] +%-5u (bit %u) %s\n", i, byte_off, bit_off, mname);
                    else
                        printf("  [%3u] +%-5u %s\n", i, byte_off, mname);
                    if (mname[0] == '\0' || strcmp(mname,"peer")==0 || strcmp(mname,"base")==0 ||
                        strcmp(mname,"c")==0 || strcmp(mname,"stream")==0 || strcmp(mname,"outqueue")==0) {
                        char pfx[64];
                        snprintf(pfx, sizeof pfx, "    %s.", mname[0] ? mname : "(anon)");
                        dump_members_recursive(m[i].type, byte_off, pfx, 0);
                    }
                }
                p += vlen * sizeof(struct btf_member);
                return;
            }
            p += vlen * sizeof(struct btf_member);
        } else {
            advance_type(&p, kind, vlen);
        }
        tid++;
    }
}

int main(int argc, char **argv) {
    const char *path = "/sys/kernel/btf/vmlinux";
    if (argc > 1) path = argv[1];

    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open btf"); return 1; }
    struct stat st;
    fstat(fd, &st);
    btf_size = st.st_size;
    btf_data = malloc(btf_size);
    if (!btf_data) { perror("malloc"); return 1; }
    size_t rd = 0;
    while (rd < btf_size) {
        ssize_t n = read(fd, btf_data + rd, btf_size - rd);
        if (n <= 0) break;
        rd += n;
    }
    close(fd);

    hdr = (struct btf_header *)btf_data;
    if (hdr->magic != BTF_MAGIC) {
        printf("BAD BTF MAGIC: 0x%04x\n", hdr->magic);
        return 1;
    }
    printf("BTF v%u, hdr=%u, types=%u bytes, strings=%u bytes\n",
           hdr->version, hdr->hdr_len, hdr->type_len, hdr->str_len);

    type_sec = btf_data + hdr->hdr_len + hdr->type_off;
    str_sec = (char *)(btf_data + hdr->hdr_len + hdr->str_off);

    for (int i = 0; queries[i].struct_name; i++) {
        find_struct_offsets(queries[i].struct_name, queries[i].members);
    }

    printf("\n=== FULL STRUCT DUMPS ===\n");
    dump_all_members("sctp_transport");
    dump_all_members("sctp_association");
    dump_all_members("subprocess_info");
    dump_all_members("sctp_pf");
    dump_all_members("sctp_af");
    dump_all_members("sctp_packet");
    dump_all_members("pcpu_hot");
    dump_all_members("sctp_sock");
    dump_all_members("sctp_ep_common");
    dump_all_members("work_struct");

    return 0;
}
