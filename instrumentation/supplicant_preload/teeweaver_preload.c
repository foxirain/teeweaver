#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/tee.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/*
 * This interposer changes only an untrusted Normal-World process. It observes
 * the public Linux TEE supplicant ABI and applies faults that a malicious
 * supplicant could perform itself.
 */

/* Public arm_ffa_user ABI (kept local so the interposer builds independently). */
#define FFA_IOC_MAGIC 0xf0
#define FFA_IOC_BASE 0

struct tw_ffa_ioctl_msg_args {
	uint64_t args[5];
	uint16_t dst_id;
};

struct tw_ffa_ioctl_shm_desc {
	uint64_t handle;
	uint64_t size;
	uint16_t dst_id;
};

struct tw_ffa_ioctl_buf_desc {
	uint64_t handle;
	uint64_t buf_ptr;
	uint64_t buf_len;
};

#define TW_FFA_IOC_MSG_SEND \
	_IOWR(FFA_IOC_MAGIC, FFA_IOC_BASE + 1, struct tw_ffa_ioctl_msg_args)
#define TW_FFA_IOC_SHM_INIT \
	_IOWR(FFA_IOC_MAGIC, FFA_IOC_BASE + 2, struct tw_ffa_ioctl_shm_desc)
#define TW_FFA_IOC_SHM_DEINIT \
	_IOW(FFA_IOC_MAGIC, FFA_IOC_BASE + 3, struct tw_ffa_ioctl_shm_desc)
#define TW_FFA_IOC_SHM_READ \
	_IOW(FFA_IOC_MAGIC, FFA_IOC_BASE + 4, struct tw_ffa_ioctl_buf_desc)
#define TW_FFA_IOC_SHM_WRITE \
	_IOW(FFA_IOC_MAGIC, FFA_IOC_BASE + 5, struct tw_ffa_ioctl_buf_desc)

#define TW_SPMC_TEST_OK UINT64_C(0xaa)
#define TW_EP_TRY_R_ACCESS 3
#define TW_EP_TRY_W_ACCESS 4
#define TW_EP_RETRIEVE 5
#define TW_EP_RELINQUISH 6
#define TW_FFA_HANDLE_LOW_INDEX 1
#define TW_FFA_HANDLE_HIGH_INDEX 2

enum fault_kind {
	FAULT_NONE,
	FAULT_DELAY,
	FAULT_FORCE_RET,
	FAULT_SWAP_PAIR,
	FAULT_FLIP_MEMREF,
};

struct fault_config {
	enum fault_kind kind;
	int func;
	unsigned long occurrence;
	unsigned long long value;
	unsigned param_index;
	unsigned long long byte_offset;
	unsigned char byte_mask;
};

struct fd_record {
	bool used;
	int id;
	unsigned generation;
	uint64_t size;
};

struct id_record {
	bool used;
	int id;
	unsigned generation;
};

struct mapping_record {
	bool used;
	void *base;
	size_t length;
	int id;
	unsigned generation;
};

struct swap_record {
	bool waiting;
	bool attempted;
	unsigned long cycle;
	unsigned long completed_cycle;
	__u64 *first_id;
	uint32_t first_num_params;
};

enum ffa_fault_kind {
	FFA_FAULT_NONE,
	FFA_FAULT_DELAY,
	FFA_FAULT_DUPLICATE,
	FFA_FAULT_FLIP_HANDLE,
};

struct ffa_fault_config {
	enum ffa_fault_kind kind;
	bool reclaim_target;
	int action;
	unsigned long occurrence;
	uint64_t value;
};

struct ffa_handle_record {
	bool used;
	uint64_t handle;
	unsigned generation;
	bool live;
	uint16_t receiver;
};

struct ffa_binding_record {
	bool used;
	uint16_t receiver;
	uint64_t handle;
	unsigned generation;
	unsigned references;
};

#define MAX_TRACKED_FD 4096
#define MAX_TRACKED_ID 4096
#define MAX_TRACKED_FUNC 256
#define MAX_TRACKED_MAPPING 4096
#define SWAP_WAIT_NSEC 100000000L
#define MAX_FFA_HANDLES 1024
#define MAX_FFA_BINDINGS 1024
#define MAX_FFA_ACTION 64

static pthread_once_t init_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t state_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t trace_order_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t swap_condition = PTHREAD_COND_INITIALIZER;
static int trace_fd = -1;
static unsigned long trace_sequence;
static unsigned long recv_occurrence[MAX_TRACKED_FUNC];
static struct fd_record fd_records[MAX_TRACKED_FD];
static struct id_record id_records[MAX_TRACKED_ID];
static struct mapping_record mapping_records[MAX_TRACKED_MAPPING];
static struct fault_config fault;
static struct ffa_fault_config ffa_fault;
static struct swap_record swap_record;
static bool client_trace_enabled;
static bool ffa_trace_enabled;
static bool supplicant_process;
static struct ffa_handle_record ffa_handles[MAX_FFA_HANDLES];
static struct ffa_binding_record ffa_bindings[MAX_FFA_BINDINGS];
static unsigned long ffa_action_occurrence[MAX_FFA_ACTION];
static unsigned long ffa_reclaim_occurrence;

static __thread uint32_t current_func;
static __thread uint64_t current_request;
static __thread unsigned long current_occurrence;
static __thread bool current_has_request;
static __thread const char *last_flip_status;
static __thread int last_flip_errno;
static __thread int last_flip_before = -1;
static __thread int last_flip_after = -1;

static int (*real_ioctl_fn)(int, unsigned long, ...);
static int (*real_close_fn)(int);
static void *(*real_mmap_fn)(void *, size_t, int, int, int, off_t);
static void *(*real_mmap64_fn)(void *, size_t, int, int, int, off64_t);
static int (*real_munmap_fn)(void *, size_t);
static uint32_t (*real_teec_open_session_fn)(void *, void *, const void *,
					     uint32_t, const void *, void *,
					     uint32_t *);
static void (*real_teec_close_session_fn)(void *);
static uint32_t (*real_teec_invoke_command_fn)(void *, uint32_t, void *,
					       uint32_t *);
static void (*real_teec_request_cancellation_fn)(void *);

static long thread_id(void)
{
	return syscall(SYS_gettid);
}

static uint64_t monotonic_ns(void)
{
	struct timespec now = { 0 };

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (uint64_t)now.tv_sec * UINT64_C(1000000000) +
	       (uint64_t)now.tv_nsec;
}

static void parse_fault(const char *text)
{
	char *copy = NULL;
	char *save = NULL;
	char *part[6] = { 0 };
	size_t n = 0;

	if (!text || !*text)
		return;
	copy = strdup(text);
	if (!copy)
		return;
	for (n = 0; n < 6; n++) {
		part[n] = strtok_r(n ? NULL : copy, ":", &save);
		if (!part[n])
			break;
	}
	if (!part[0] || !part[1])
		goto out;

	fault.func = !strcmp(part[1], "*") ? -1 : (int)strtol(part[1], NULL, 0);
	if (!strcmp(part[0], "delay") && part[2] && part[3]) {
		fault.kind = FAULT_DELAY;
		fault.occurrence = strtoul(part[2], NULL, 0);
		fault.value = strtoull(part[3], NULL, 0);
	} else if (!strcmp(part[0], "force_ret") && part[2] && part[3]) {
		fault.kind = FAULT_FORCE_RET;
		fault.occurrence = strtoul(part[2], NULL, 0);
		fault.value = strtoull(part[3], NULL, 0);
	} else if (!strcmp(part[0], "swap_pair")) {
		fault.kind = FAULT_SWAP_PAIR;
		if (part[2])
			fault.occurrence = strtoul(part[2], NULL, 0);
	} else if (!strcmp(part[0], "flip_memref") && part[2] && part[3] &&
		   part[4] && part[5]) {
		fault.kind = FAULT_FLIP_MEMREF;
		fault.occurrence = strtoul(part[2], NULL, 0);
		fault.param_index = strtoul(part[3], NULL, 0);
		fault.byte_offset = strtoull(part[4], NULL, 0);
		fault.byte_mask = (unsigned char)strtoul(part[5], NULL, 0);
	}
out:
	free(copy);
}

static void parse_ffa_fault(const char *text)
{
	char *copy = NULL;
	char *save = NULL;
	char *part[4] = { 0 };
	size_t n = 0;

	if (!text || !*text)
		return;
	copy = strdup(text);
	if (!copy)
		return;
	for (n = 0; n < 4; n++) {
		part[n] = strtok_r(n ? NULL : copy, ":", &save);
		if (!part[n])
			break;
	}
	if (!part[0] || !part[1] || !part[2])
		goto out;
	ffa_fault.reclaim_target = !strcmp(part[1], "reclaim");
	ffa_fault.action = ffa_fault.reclaim_target ? -1 :
		(int)strtol(part[1], NULL, 0);
	ffa_fault.occurrence = strtoul(part[2], NULL, 0);
	if (!strcmp(part[0], "ffa_delay") && part[3]) {
		ffa_fault.kind = FFA_FAULT_DELAY;
		ffa_fault.value = strtoull(part[3], NULL, 0);
	} else if (!strcmp(part[0], "ffa_duplicate")) {
		ffa_fault.kind = FFA_FAULT_DUPLICATE;
	} else if (!strcmp(part[0], "ffa_flip_handle") && part[3]) {
		ffa_fault.kind = FFA_FAULT_FLIP_HANDLE;
		ffa_fault.value = strtoull(part[3], NULL, 0);
	}
out:
	free(copy);
}

static void initialize(void)
{
	const char *path = getenv("TEEWEAVER_TRACE");
	const char *client_trace = getenv("TEEWEAVER_TRACE_CLIENT");
	const char *ffa_trace = getenv("TEEWEAVER_TRACE_FFA");
	const char *role = getenv("TEEWEAVER_ROLE");
	char executable[256] = { 0 };
	ssize_t executable_length = 0;

	real_ioctl_fn = dlsym(RTLD_NEXT, "ioctl");
	real_close_fn = dlsym(RTLD_NEXT, "close");
	real_mmap_fn = dlsym(RTLD_NEXT, "mmap");
	real_mmap64_fn = dlsym(RTLD_NEXT, "mmap64");
	real_munmap_fn = dlsym(RTLD_NEXT, "munmap");
	real_teec_open_session_fn = dlsym(RTLD_NEXT, "TEEC_OpenSession");
	real_teec_close_session_fn = dlsym(RTLD_NEXT, "TEEC_CloseSession");
	real_teec_invoke_command_fn = dlsym(RTLD_NEXT, "TEEC_InvokeCommand");
	real_teec_request_cancellation_fn =
		dlsym(RTLD_NEXT, "TEEC_RequestCancellation");
	executable_length = readlink("/proc/self/exe", executable,
				     sizeof(executable) - 1);
	if (executable_length > 0)
		executable[executable_length] = '\0';
	supplicant_process =
		(role && !strcmp(role, "supplicant")) ||
		strstr(executable, "tee-supplicant");
	parse_fault(getenv("TEEWEAVER_FAULT"));
	parse_ffa_fault(getenv("TEEWEAVER_FFA_FAULT"));
	client_trace_enabled = client_trace && !strcmp(client_trace, "1");
	ffa_trace_enabled = ffa_trace && !strcmp(ffa_trace, "1");
	if (!path || !*path)
		path = "/tmp/teeweaver.jsonl";
	trace_fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
}

static uint64_t hash_params(const struct tee_ioctl_param *params, size_t count)
{
	const unsigned char *bytes = (const unsigned char *)params;
	size_t length = count * sizeof(*params);
	uint64_t hash = UINT64_C(1469598103934665603);
	size_t n = 0;

	for (n = 0; n < length; n++) {
		hash ^= bytes[n];
		hash *= UINT64_C(1099511628211);
	}
	return hash;
}

static uint64_t memref_mask(const struct tee_ioctl_param *params, size_t count)
{
	uint64_t mask = 0;
	size_t n = 0;

	for (n = 0; n < count && n < 64; n++) {
		uint64_t type = params[n].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK;

		if (type == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT ||
		    type == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT ||
		    type == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT)
			mask |= UINT64_C(1) << n;
	}
	return mask;
}

static int first_memref(const struct tee_ioctl_param *params, size_t count,
			uint64_t *offset, uint64_t *size, uint64_t *id)
{
	size_t n = 0;

	for (n = 0; n < count; n++) {
		uint64_t type = params[n].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK;

		if (type == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT ||
		    type == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT ||
		    type == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT) {
			*offset = params[n].a;
			*size = params[n].b;
			*id = params[n].c;
			return (int)n;
		}
	}
	return -1;
}

static void append_trace(const char *line)
{
	ssize_t written = 0;

	if (trace_fd < 0)
		return;
	written = write(trace_fd, line, strlen(line));
	(void)written;
}

static void trace_rpc(const char *op, uint32_t func, uint64_t request,
		      uint64_t claims_request, uint32_t num_params,
		      const struct tee_ioctl_param *params, uint64_t param_hash,
		      unsigned long occurrence, const char *fault_name,
		      int ioctl_result)
{
	char line[640];
	unsigned long seq = 0;
	uint64_t offset = 0;
	uint64_t size = 0;
	uint64_t id = 0;
	int memref_index = first_memref(params, num_params, &offset, &size, &id);
	int length = 0;

	pthread_mutex_lock(&state_mutex);
	seq = ++trace_sequence;
	length = snprintf(line, sizeof(line),
		"{\"seq\":%lu,\"time_ns\":%llu,\"op\":\"%s\","
		"\"actor\":\"supplicant-%ld\","
		"\"request\":\"%llu\",\"claims_request\":\"%llu\","
		"\"func\":%u,\"occurrence\":%lu,\"num_params\":%u,"
		"\"memref_mask\":%llu,\"first_memref_index\":%d,"
		"\"first_memref_offset\":%llu,\"first_memref_size\":%llu,"
		"\"first_memref_id\":%llu,\"param_hash\":\"%016llx\","
		"\"ioctl_result\":%d,\"fault_errno\":%d,"
		"\"fault_param\":%u,\"fault_offset\":%llu,"
		"\"fault_before\":%d,\"fault_after\":%d%s%s%s}\n",
		seq, (unsigned long long)monotonic_ns(), op, thread_id(),
		(unsigned long long)request,
		(unsigned long long)claims_request, func, occurrence, num_params,
		(unsigned long long)memref_mask(params, num_params), memref_index,
		(unsigned long long)offset, (unsigned long long)size,
		(unsigned long long)id,
		(unsigned long long)param_hash, ioctl_result, last_flip_errno,
		fault.param_index, (unsigned long long)fault.byte_offset,
		last_flip_before, last_flip_after,
		fault_name ? ",\"fault\":\"" : "",
		fault_name ? fault_name : "", fault_name ? "\"" : "");
	if (length > 0 && (size_t)length < sizeof(line))
		append_trace(line);
	pthread_mutex_unlock(&state_mutex);
}

static void trace_shm(const char *op, int id, unsigned generation, uint64_t size)
{
	char line[384];
	unsigned long seq = 0;
	int length = 0;

	pthread_mutex_lock(&state_mutex);
	seq = ++trace_sequence;
	length = snprintf(line, sizeof(line),
		"{\"seq\":%lu,\"time_ns\":%llu,\"op\":\"%s\","
		"\"actor\":\"supplicant-%ld\","
		"\"object\":\"%d\",\"generation\":%u,\"size\":%llu}\n",
		seq, (unsigned long long)monotonic_ns(), op, thread_id(), id,
		generation, (unsigned long long)size);
	if (length > 0 && (size_t)length < sizeof(line))
		append_trace(line);
	pthread_mutex_unlock(&state_mutex);
}

static void trace_client_at(uint64_t time_ns, const char *op,
			    const void *session, const void *operation,
			    uint32_t command, uint32_t result)
{
	char line[512];
	unsigned long seq = 0;
	int length = 0;

	pthread_mutex_lock(&state_mutex);
	seq = ++trace_sequence;
	length = snprintf(line, sizeof(line),
		"{\"seq\":%lu,\"time_ns\":%llu,\"op\":\"%s\","
		"\"actor\":\"client-%ld\","
		"\"session\":\"%llx\",\"operation\":\"%llx\","
		"\"command\":%u,\"result\":%u}\n",
		seq, (unsigned long long)time_ns, op, thread_id(),
		(unsigned long long)(uintptr_t)session,
		(unsigned long long)(uintptr_t)operation, command, result);
	if (length > 0 && (size_t)length < sizeof(line))
		append_trace(line);
	pthread_mutex_unlock(&state_mutex);
}

static void trace_client(const char *op, const void *session,
			 const void *operation, uint32_t command,
			 uint32_t result)
{
	trace_client_at(monotonic_ns(), op, session, operation, command, result);
}

static const char *ffa_fault_name(enum ffa_fault_kind kind)
{
	switch (kind) {
	case FFA_FAULT_DELAY:
		return "delay";
	case FFA_FAULT_DUPLICATE:
		return "duplicate";
	case FFA_FAULT_FLIP_HANDLE:
		return "flip-handle";
	default:
		return NULL;
	}
}

static void trace_ffa_raw(const char *op, uint16_t receiver, int action,
			  uint64_t handle, bool has_handle,
			  unsigned generation, unsigned long occurrence,
			  int ioctl_result, int ioctl_errno, uint64_t response,
			  const char *fault_name, bool duplicate)
{
	char line[768];
	char handle_fields[160] = { 0 };
	char fault_fields[160] = { 0 };
	const char *call_kind = !strcmp(op, "ffa_reclaim_attempt") ?
				"reclaim" : "message";
	unsigned long seq = 0;
	int length = 0;

	if (has_handle)
		snprintf(handle_fields, sizeof(handle_fields),
			 ",\"object\":\"%016llx\",\"generation\":%u",
			 (unsigned long long)handle, generation);
	if (fault_name)
		snprintf(fault_fields, sizeof(fault_fields),
			 ",\"fault\":\"%s\",\"duplicate\":%s",
			 fault_name, duplicate ? "true" : "false");
	pthread_mutex_lock(&state_mutex);
	seq = ++trace_sequence;
	length = snprintf(line, sizeof(line),
		"{\"seq\":%lu,\"time_ns\":%llu,\"op\":\"%s\","
		"\"actor\":\"ffa-client-%ld\",\"process\":\"%d\","
		"\"call\":\"%d:%ld:%s:%d:%lu:%u\","
		"\"receiver\":\"%u\","
		"\"action\":%d,\"occurrence\":%lu,\"ioctl_result\":%d,"
		"\"ioctl_errno\":%d,"
		"\"response\":%llu%s%s}\n",
		seq, (unsigned long long)monotonic_ns(), op, thread_id(), getpid(),
		getpid(), thread_id(), call_kind, action, occurrence,
		duplicate ? 1U : 0U,
		receiver, action, occurrence, ioctl_result, ioctl_errno,
		(unsigned long long)response,
		handle_fields, fault_fields);
	if (length > 0 && (size_t)length < sizeof(line))
		append_trace(line);
	pthread_mutex_unlock(&state_mutex);
}

static void trace_ffa_call_issue(const char *kind, uint16_t receiver, int action,
				 uint64_t handle, bool has_handle,
				 unsigned generation, unsigned long occurrence,
				 bool duplicate)
{
	char line[640];
	char handle_fields[160] = { 0 };
	unsigned long seq = 0;
	int length = 0;

	if (has_handle)
		snprintf(handle_fields, sizeof(handle_fields),
			 ",\"object\":\"%016llx\",\"generation\":%u",
			 (unsigned long long)handle, generation);
	pthread_mutex_lock(&state_mutex);
	seq = ++trace_sequence;
	length = snprintf(line, sizeof(line),
		"{\"seq\":%lu,\"time_ns\":%llu,\"op\":\"ffa_call_issue\","
		"\"actor\":\"ffa-client-%ld\",\"process\":\"%d\","
		"\"call\":\"%d:%ld:%s:%d:%lu:%u\",\"target\":\"%s\","
		"\"receiver\":\"%u\",\"action\":%d,\"occurrence\":%lu,"
		"\"duplicate\":%s%s}\n",
		seq, (unsigned long long)monotonic_ns(), thread_id(), getpid(),
		getpid(), thread_id(), kind, action, occurrence,
		duplicate ? 1U : 0U, kind,
		receiver, action, occurrence, duplicate ? "true" : "false",
		handle_fields);
	if (length > 0 && (size_t)length < sizeof(line))
		append_trace(line);
	pthread_mutex_unlock(&state_mutex);
}

static void trace_ffa_lifecycle(const char *op, uint16_t receiver,
				uint64_t handle, unsigned generation,
				const char *access, const char *fault_name)
{
	char line[640];
	char access_field[80] = { 0 };
	char fault_field[96] = { 0 };
	unsigned long seq = 0;
	int length = 0;

	if (access)
		snprintf(access_field, sizeof(access_field),
			 ",\"access\":\"%s\"", access);
	if (fault_name)
		snprintf(fault_field, sizeof(fault_field),
			 ",\"fault\":\"%s\"", fault_name);
	pthread_mutex_lock(&state_mutex);
	seq = ++trace_sequence;
	length = snprintf(line, sizeof(line),
		"{\"seq\":%lu,\"time_ns\":%llu,\"op\":\"%s\","
		"\"actor\":\"ffa-client-%ld\",\"process\":\"%d\","
		"\"object\":\"%016llx\",\"generation\":%u,"
		"\"owner\":\"normal-world-%d\",\"receiver\":\"%u\"%s%s}\n",
		seq, (unsigned long long)monotonic_ns(), op, thread_id(), getpid(),
		(unsigned long long)handle, generation, getpid(), receiver,
		access_field, fault_field);
	if (length > 0 && (size_t)length < sizeof(line))
		append_trace(line);
	pthread_mutex_unlock(&state_mutex);
}

static void trace_ffa_fault(const char *name, const char *target,
			    unsigned long occurrence, uint64_t before,
			    uint64_t after)
{
	char line[512];
	unsigned long seq = 0;
	int length = 0;

	pthread_mutex_lock(&state_mutex);
	seq = ++trace_sequence;
	length = snprintf(line, sizeof(line),
		"{\"seq\":%lu,\"time_ns\":%llu,\"op\":\"ffa_fault\","
		"\"actor\":\"normal-world-%d\",\"process\":\"%d\","
		"\"fault\":\"%s\","
		"\"target\":\"%s\",\"occurrence\":%lu,"
		"\"before\":\"%016llx\",\"after\":\"%016llx\"}\n",
		seq, (unsigned long long)monotonic_ns(), getpid(), getpid(), name, target,
		occurrence, (unsigned long long)before, (unsigned long long)after);
	if (length > 0 && (size_t)length < sizeof(line))
		append_trace(line);
	pthread_mutex_unlock(&state_mutex);
}

static struct ffa_handle_record *find_ffa_handle_locked(uint64_t handle,
						 size_t *empty)
{
	size_t n = 0;

	if (empty)
		*empty = MAX_FFA_HANDLES;
	for (n = 0; n < MAX_FFA_HANDLES; n++) {
		if (ffa_handles[n].used && ffa_handles[n].handle == handle)
			return &ffa_handles[n];
		if (empty && !ffa_handles[n].used && *empty == MAX_FFA_HANDLES)
			*empty = n;
	}
	return NULL;
}

static unsigned register_ffa_handle(uint64_t handle, uint16_t receiver)
{
	struct ffa_handle_record *record = NULL;
	size_t empty = MAX_FFA_HANDLES;
	unsigned generation = 0;

	pthread_mutex_lock(&state_mutex);
	record = find_ffa_handle_locked(handle, &empty);
	if (!record && empty < MAX_FFA_HANDLES) {
		record = &ffa_handles[empty];
		record->used = true;
		record->handle = handle;
	}
	if (record) {
		generation = ++record->generation;
		record->live = true;
		record->receiver = receiver;
	}
	pthread_mutex_unlock(&state_mutex);
	return generation;
}

static bool lookup_ffa_handle(uint64_t handle, unsigned *generation,
			      bool *live, uint16_t *receiver)
{
	struct ffa_handle_record *record = NULL;
	bool found = false;

	pthread_mutex_lock(&state_mutex);
	record = find_ffa_handle_locked(handle, NULL);
	if (record) {
		*generation = record->generation;
		*live = record->live;
		*receiver = record->receiver;
		found = true;
	}
	pthread_mutex_unlock(&state_mutex);
	return found;
}

static void mark_ffa_reclaimed(uint64_t handle)
{
	struct ffa_handle_record *record = NULL;

	pthread_mutex_lock(&state_mutex);
	record = find_ffa_handle_locked(handle, NULL);
	if (record)
		record->live = false;
	pthread_mutex_unlock(&state_mutex);
}

static void update_ffa_binding(uint16_t receiver, uint64_t handle,
			       unsigned generation, int delta)
{
	size_t n = 0;
	size_t empty = MAX_FFA_BINDINGS;
	struct ffa_binding_record *record = NULL;

	pthread_mutex_lock(&state_mutex);
	for (n = 0; n < MAX_FFA_BINDINGS; n++) {
		if (ffa_bindings[n].used && ffa_bindings[n].receiver == receiver &&
		    ffa_bindings[n].handle == handle &&
		    ffa_bindings[n].generation == generation) {
			record = &ffa_bindings[n];
			break;
		}
		if (!ffa_bindings[n].used && empty == MAX_FFA_BINDINGS)
			empty = n;
	}
	if (!record && delta > 0 && empty < MAX_FFA_BINDINGS) {
		record = &ffa_bindings[empty];
		record->used = true;
		record->receiver = receiver;
		record->handle = handle;
		record->generation = generation;
	}
	if (record && delta > 0)
		record->references += (unsigned)delta;
	else if (record && delta < 0 && record->references)
		record->references--;
	pthread_mutex_unlock(&state_mutex);
}

static bool unique_ffa_binding(uint16_t receiver, uint64_t *handle,
			       unsigned *generation)
{
	size_t n = 0;
	unsigned matches = 0;

	pthread_mutex_lock(&state_mutex);
	for (n = 0; n < MAX_FFA_BINDINGS; n++) {
		if (!ffa_bindings[n].used ||
		    ffa_bindings[n].receiver != receiver ||
		    !ffa_bindings[n].references)
			continue;
		matches++;
		*handle = ffa_bindings[n].handle;
		*generation = ffa_bindings[n].generation;
	}
	pthread_mutex_unlock(&state_mutex);
	return matches == 1;
}

static bool ffa_message_handle(const struct tw_ffa_ioctl_msg_args *message,
			       int action, uint64_t *handle)
{
	if (action != TW_EP_RETRIEVE && action != TW_EP_RELINQUISH)
		return false;
	*handle = (message->args[TW_FFA_HANDLE_LOW_INDEX] & UINT64_C(0xffffffff)) |
		 (message->args[TW_FFA_HANDLE_HIGH_INDEX] << 32);
	return true;
}

static void record_ffa_message(const struct tw_ffa_ioctl_msg_args *input,
			       const struct tw_ffa_ioctl_msg_args *output,
			       int result, int ioctl_errno,
			       unsigned long occurrence,
			       const char *fault_name, bool duplicate)
{
	int action = (int)input->args[0];
	uint64_t handle = 0;
	unsigned generation = 0;
	bool live = false;
	uint16_t shared_receiver = 0;
	bool has_handle = ffa_message_handle(input, action, &handle);
	bool accepted = result >= 0 && output->args[0] == TW_SPMC_TEST_OK;

	if (has_handle)
		lookup_ffa_handle(handle, &generation, &live, &shared_receiver);
	trace_ffa_raw("ffa_direct_message", input->dst_id, action, handle,
		      has_handle, generation, occurrence, result,
		      result < 0 ? ioctl_errno : 0,
		      output->args[0],
		      fault_name, duplicate);
	if (!accepted)
		return;
	if (action == TW_EP_RETRIEVE) {
		update_ffa_binding(input->dst_id, handle, generation, 1);
		trace_ffa_lifecycle("ffa_retrieve", input->dst_id, handle,
				    generation, NULL, fault_name);
	} else if (action == TW_EP_RELINQUISH) {
		trace_ffa_lifecycle("ffa_relinquish", input->dst_id, handle,
				    generation, NULL, fault_name);
		update_ffa_binding(input->dst_id, handle, generation, -1);
	} else if (action == TW_EP_TRY_R_ACCESS ||
		   action == TW_EP_TRY_W_ACCESS) {
		if (unique_ffa_binding(input->dst_id, &handle, &generation))
			trace_ffa_lifecycle("ffa_access", input->dst_id, handle,
					    generation,
					    action == TW_EP_TRY_R_ACCESS ?
					    "read" : "write", fault_name);
		else
			trace_ffa_raw("ffa_access_ambiguous", input->dst_id, action,
				      0, false, 0, occurrence, result,
				      result < 0 ? ioctl_errno : 0,
				      output->args[0], fault_name,
				      duplicate);
	}
}

static bool ffa_fault_matches(int action, bool reclaim,
			      unsigned long occurrence)
{
	if (ffa_fault.kind == FFA_FAULT_NONE ||
	    ffa_fault.reclaim_target != reclaim)
		return false;
	if (!reclaim && ffa_fault.action != action)
		return false;
	return !ffa_fault.occurrence || ffa_fault.occurrence == occurrence;
}

static void ffa_fault_delay(void)
{
	struct timespec delay = {
		.tv_sec = (time_t)(ffa_fault.value / UINT64_C(1000000)),
		.tv_nsec = (long)((ffa_fault.value % UINT64_C(1000000)) * 1000),
	};

	nanosleep(&delay, NULL);
}

static unsigned next_generation_locked(int id)
{
	size_t n = 0;
	size_t empty = MAX_TRACKED_ID;

	for (n = 0; n < MAX_TRACKED_ID; n++) {
		if (id_records[n].used && id_records[n].id == id)
			return ++id_records[n].generation;
		if (!id_records[n].used && empty == MAX_TRACKED_ID)
			empty = n;
	}
	if (empty == MAX_TRACKED_ID)
		return 0;
	id_records[empty].used = true;
	id_records[empty].id = id;
	id_records[empty].generation = 1;
	return 1;
}

static void track_shm_fd(int fd, int id, uint64_t size)
{
	unsigned generation = 0;

	pthread_mutex_lock(&state_mutex);
	generation = next_generation_locked(id);
	if (fd >= 0 && fd < MAX_TRACKED_FD) {
		fd_records[fd].used = true;
		fd_records[fd].id = id;
		fd_records[fd].generation = generation;
		fd_records[fd].size = size;
	}
	pthread_mutex_unlock(&state_mutex);
	trace_shm("shm_register", id, generation, size);
	trace_shm("shm_fd", fd, generation, (uint64_t)(unsigned)id);
}

static void track_mapping(void *base, size_t length, int fd)
{
	size_t n = 0;
	int id = 0;
	unsigned generation = 0;
	bool tracked = false;

	if (fd < 0 || fd >= MAX_TRACKED_FD || base == MAP_FAILED)
		return;
	pthread_mutex_lock(&state_mutex);
	if (!fd_records[fd].used)
		goto out;
	for (n = 0; n < MAX_TRACKED_MAPPING; n++) {
		if (!mapping_records[n].used) {
			mapping_records[n].used = true;
			mapping_records[n].base = base;
			mapping_records[n].length = length;
			mapping_records[n].id = fd_records[fd].id;
			mapping_records[n].generation = fd_records[fd].generation;
			id = mapping_records[n].id;
			generation = mapping_records[n].generation;
			tracked = true;
			break;
		}
	}
out:
	pthread_mutex_unlock(&state_mutex);
	if (tracked)
		trace_shm("shm_map", id, generation, length);
}

static bool flip_mapped_memref(struct tee_ioctl_param *param)
{
	uint64_t type = param->attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK;
	size_t n = 0;
	int shm_fd = -1;
	size_t shm_length = 0;
	bool applied = false;

	last_flip_status = "flip-unmapped";
	last_flip_errno = 0;
	last_flip_before = -1;
	last_flip_after = -1;
	if (type != TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT &&
	    type != TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT &&
	    type != TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT) {
		last_flip_status = "flip-not-memref";
		return false;
	}
	if (fault.byte_offset >= param->b) {
		last_flip_status = "flip-out-of-param";
		return false;
	}
	pthread_mutex_lock(&state_mutex);
	for (n = 0; n < MAX_TRACKED_MAPPING; n++) {
		struct mapping_record *mapping = &mapping_records[n];
		uint64_t offset = param->a;

		if (!mapping->used || mapping->id != (int)param->c)
			continue;
		if (offset > mapping->length || param->b > mapping->length - offset ||
		    fault.byte_offset >= mapping->length - offset)
			continue;
		last_flip_before =
			((unsigned char *)mapping->base)[offset + fault.byte_offset];
		((unsigned char *)mapping->base)[offset + fault.byte_offset] ^=
			fault.byte_mask;
		last_flip_after =
			((unsigned char *)mapping->base)[offset + fault.byte_offset];
		applied = true;
		break;
	}
	if (!applied) {
		for (n = 0; n < MAX_TRACKED_FD; n++) {
			if (fd_records[n].used && fd_records[n].id == (int)param->c) {
				shm_fd = (int)n;
				shm_length = fd_records[n].size;
				break;
			}
		}
	}
	pthread_mutex_unlock(&state_mutex);
	/*
	 * A malicious supplicant owns the SHM descriptor and may create another
	 * shared mapping even when libc's mmap64 binding is not interposable. This
	 * fallback therefore uses only attacker-available Normal-World authority.
	 */
	if (!applied && shm_fd >= 0 && param->a <= shm_length &&
	    param->b <= shm_length - param->a &&
	    fault.byte_offset < shm_length - param->a) {
		void *base = real_mmap_fn(NULL, shm_length, PROT_READ | PROT_WRITE,
					 MAP_SHARED, shm_fd, 0);

		if (base != MAP_FAILED) {
			last_flip_before =
				((unsigned char *)base)[param->a + fault.byte_offset];
			((unsigned char *)base)[param->a + fault.byte_offset] ^=
				fault.byte_mask;
			last_flip_after =
				((unsigned char *)base)[param->a + fault.byte_offset];
			real_munmap_fn(base, shm_length);
			applied = true;
		} else {
			last_flip_errno = errno;
			last_flip_status = "flip-mmap-failed";
		}
	} else if (!applied && shm_fd < 0) {
		last_flip_status = "flip-no-fd";
	} else if (!applied) {
		last_flip_status = "flip-out-of-shm";
	}
	if (applied)
		last_flip_status = "flip-memref";
	return applied;
}

static bool fault_matches(void)
{
	return (fault.func < 0 || (uint32_t)fault.func == current_func) &&
	       (!fault.occurrence || fault.occurrence == current_occurrence);
}

static bool get_meta_id(struct tee_ioctl_param *params, uint32_t num_params,
			__u64 **id)
{
	if (!num_params || !(params[0].attr & TEE_IOCTL_PARAM_ATTR_META))
		return false;
	*id = &params[0].a;
	return true;
}

static bool apply_swap_pair(struct tee_iocl_supp_send_arg *send)
{
	__u64 *id = NULL;
	unsigned long my_cycle = 0;
	struct timespec deadline;
	bool applied = false;

	if (!get_meta_id(send->params, send->num_params, &id))
		return false;
	pthread_mutex_lock(&state_mutex);
	if (!swap_record.waiting) {
		if (swap_record.attempted) {
			pthread_mutex_unlock(&state_mutex);
			return false;
		}
		swap_record.attempted = true;
		swap_record.waiting = true;
		swap_record.first_id = id;
		swap_record.first_num_params = send->num_params;
		my_cycle = ++swap_record.cycle;
		clock_gettime(CLOCK_REALTIME, &deadline);
		deadline.tv_nsec += SWAP_WAIT_NSEC;
		if (deadline.tv_nsec >= 1000000000L) {
			deadline.tv_sec++;
			deadline.tv_nsec -= 1000000000L;
		}
		while (swap_record.completed_cycle < my_cycle) {
			int rc = pthread_cond_timedwait(&swap_condition, &state_mutex,
							&deadline);
			if (rc == ETIMEDOUT) {
				if (swap_record.waiting && swap_record.cycle == my_cycle)
					swap_record.waiting = false;
				break;
			}
		}
		applied = swap_record.completed_cycle >= my_cycle;
	} else if (swap_record.first_num_params == send->num_params) {
		__u64 saved = *swap_record.first_id;
		*swap_record.first_id = *id;
		*id = saved;
		swap_record.waiting = false;
		swap_record.completed_cycle = swap_record.cycle;
		applied = true;
		pthread_cond_broadcast(&swap_condition);
	}
	pthread_mutex_unlock(&state_mutex);
	return applied;
}

static const char *apply_send_fault(struct tee_iocl_supp_send_arg *send)
{
	last_flip_errno = 0;
	last_flip_before = -1;
	last_flip_after = -1;
	if (fault.kind == FAULT_NONE)
		return NULL;
	if (fault.kind == FAULT_SWAP_PAIR) {
		if (fault.func >= 0 && (uint32_t)fault.func != current_func)
			return NULL;
		if (fault.occurrence && current_occurrence < fault.occurrence)
			return NULL;
		return apply_swap_pair(send) ? "swap-pair" : NULL;
	}
	if (!fault_matches())
		return NULL;
	if (fault.kind == FAULT_DELAY) {
		struct timespec delay = {
			.tv_sec = (time_t)(fault.value / UINT64_C(1000000)),
			.tv_nsec = (long)((fault.value % UINT64_C(1000000)) * 1000),
		};
		nanosleep(&delay, NULL);
		return "delay";
	}
	if (fault.kind == FAULT_FORCE_RET) {
		send->ret = (uint32_t)fault.value;
		return "force-ret";
	}
	if (fault.kind == FAULT_FLIP_MEMREF) {
		if (fault.param_index >= send->num_params)
			return "flip-invalid-index";
		if (flip_mapped_memref(&send->params[fault.param_index]))
			return "flip-memref";
		return last_flip_status;
	}
	return NULL;
}

static bool is_ffa_request(unsigned long request)
{
	return request == TW_FFA_IOC_MSG_SEND || request == TW_FFA_IOC_SHM_INIT ||
	       request == TW_FFA_IOC_SHM_DEINIT || request == TW_FFA_IOC_SHM_READ ||
	       request == TW_FFA_IOC_SHM_WRITE;
}

static unsigned long next_ffa_occurrence(int action, bool reclaim)
{
	unsigned long occurrence = 0;

	pthread_mutex_lock(&state_mutex);
	if (reclaim)
		occurrence = ++ffa_reclaim_occurrence;
	else if (action >= 0 && action < MAX_FFA_ACTION)
		occurrence = ++ffa_action_occurrence[action];
	pthread_mutex_unlock(&state_mutex);
	return occurrence;
}

static int handle_ffa_message(int fd, unsigned long request,
			      struct tw_ffa_ioctl_msg_args *message)
{
	struct tw_ffa_ioctl_msg_args original = *message;
	struct tw_ffa_ioctl_msg_args sent = original;
	struct tw_ffa_ioctl_msg_args duplicate_message = { 0 };
	int action = (int)original.args[0];
	unsigned long occurrence = next_ffa_occurrence(action, false);
	bool matched = ffa_fault_matches(action, false, occurrence);
	const char *name = matched ? ffa_fault_name(ffa_fault.kind) : NULL;
	char target[32] = { 0 };
	uint64_t before = 0;
	uint64_t after = 0;
	uint64_t issue_handle = 0;
	unsigned issue_generation = 0;
	uint16_t issue_receiver = original.dst_id;
	bool issue_live = false;
	bool issue_has_handle = false;
	int result = 0;
	int duplicate_result = 0;
	int saved_errno = 0;
	int duplicate_errno = 0;

	snprintf(target, sizeof(target), "action-%d", action);
	if (matched && ffa_fault.kind == FFA_FAULT_FLIP_HANDLE &&
	    ffa_message_handle(&original, action, &before)) {
		after = before ^ ffa_fault.value;
		message->args[TW_FFA_HANDLE_LOW_INDEX] = after & UINT64_C(0xffffffff);
		message->args[TW_FFA_HANDLE_HIGH_INDEX] = after >> 32;
		sent = *message;
		trace_ffa_fault(name, target, occurrence, before, after);
	} else if (matched && ffa_fault.kind == FFA_FAULT_DELAY) {
		trace_ffa_fault(name, target, occurrence, 0, ffa_fault.value);
		ffa_fault_delay();
	}
	issue_has_handle = ffa_message_handle(&sent, action, &issue_handle);
	if (issue_has_handle)
		lookup_ffa_handle(issue_handle, &issue_generation, &issue_live,
				  &issue_receiver);
	trace_ffa_call_issue("message", sent.dst_id, action, issue_handle,
			     issue_has_handle, issue_generation, occurrence, false);
	result = real_ioctl_fn(fd, request, message);
	saved_errno = errno;
	record_ffa_message(&sent, message, result, saved_errno, occurrence,
			   matched && ffa_fault.kind != FFA_FAULT_DUPLICATE ?
			   name : NULL, false);
	if (matched && ffa_fault.kind == FFA_FAULT_DUPLICATE) {
		trace_ffa_fault(name, target, occurrence, 0, 0);
		duplicate_message = original;
		issue_handle = 0;
		issue_generation = 0;
		issue_has_handle = ffa_message_handle(&original, action,
						      &issue_handle);
		if (issue_has_handle)
			lookup_ffa_handle(issue_handle, &issue_generation,
					  &issue_live, &issue_receiver);
		trace_ffa_call_issue("message", original.dst_id, action,
				     issue_handle, issue_has_handle,
				     issue_generation, occurrence, true);
		duplicate_result = real_ioctl_fn(fd, request, &duplicate_message);
		duplicate_errno = errno;
		record_ffa_message(&original, &duplicate_message, duplicate_result,
				   duplicate_errno, occurrence, name, true);
	}
	if (matched && ffa_fault.kind == FFA_FAULT_FLIP_HANDLE) {
		message->args[TW_FFA_HANDLE_LOW_INDEX] =
			original.args[TW_FFA_HANDLE_LOW_INDEX];
		message->args[TW_FFA_HANDLE_HIGH_INDEX] =
			original.args[TW_FFA_HANDLE_HIGH_INDEX];
	}
	errno = saved_errno;
	return result;
}

static int handle_ffa_reclaim(int fd, unsigned long request,
			      struct tw_ffa_ioctl_shm_desc *description)
{
	struct tw_ffa_ioctl_shm_desc original = *description;
	struct tw_ffa_ioctl_shm_desc duplicate_description = original;
	unsigned long occurrence = next_ffa_occurrence(-1, true);
	bool matched = ffa_fault_matches(-1, true, occurrence);
	const char *name = matched ? ffa_fault_name(ffa_fault.kind) : NULL;
	uint64_t handle = original.handle;
	unsigned generation = 0;
	bool live = false;
	uint16_t receiver = original.dst_id;
	int result = 0;
	int duplicate_result = 0;
	int saved_errno = 0;
	int duplicate_errno = 0;

	if (matched && ffa_fault.kind == FFA_FAULT_FLIP_HANDLE) {
		description->handle ^= ffa_fault.value;
		handle = description->handle;
		trace_ffa_fault(name, "reclaim", occurrence, original.handle, handle);
	} else if (matched && ffa_fault.kind == FFA_FAULT_DELAY) {
		trace_ffa_fault(name, "reclaim", occurrence, 0, ffa_fault.value);
		ffa_fault_delay();
	}
	lookup_ffa_handle(handle, &generation, &live, &receiver);
	trace_ffa_call_issue("reclaim", receiver, -1, handle, true, generation,
			     occurrence, false);
	result = real_ioctl_fn(fd, request, description);
	saved_errno = errno;
	trace_ffa_raw("ffa_reclaim_attempt", receiver, -1, handle, true,
		      generation, occurrence, result,
		      result < 0 ? saved_errno : 0, 0,
		      matched && ffa_fault.kind != FFA_FAULT_DUPLICATE ?
		      name : NULL, false);
	if (result >= 0) {
		trace_ffa_lifecycle("ffa_reclaim", receiver, handle, generation,
				    NULL,
				    matched && ffa_fault.kind != FFA_FAULT_DUPLICATE ?
				    name : NULL);
		mark_ffa_reclaimed(handle);
	}
	if (matched && ffa_fault.kind == FFA_FAULT_DUPLICATE) {
		trace_ffa_fault(name, "reclaim", occurrence, handle, handle);
		trace_ffa_call_issue("reclaim", receiver, -1,
				     duplicate_description.handle, true, generation,
				     occurrence, true);
		duplicate_result = real_ioctl_fn(fd, request, &duplicate_description);
		duplicate_errno = errno;
		lookup_ffa_handle(duplicate_description.handle, &generation, &live,
				  &receiver);
		trace_ffa_raw("ffa_reclaim_attempt", receiver, -1,
			      duplicate_description.handle, true, generation,
			      occurrence, duplicate_result,
			      duplicate_result < 0 ? duplicate_errno : 0, 0,
			      name, true);
		if (duplicate_result >= 0) {
			trace_ffa_lifecycle("ffa_reclaim", receiver,
					    duplicate_description.handle, generation,
					    NULL, name);
			mark_ffa_reclaimed(duplicate_description.handle);
		}
	}
	if (matched && ffa_fault.kind == FFA_FAULT_FLIP_HANDLE)
		description->handle = original.handle;
	errno = saved_errno;
	return result;
}

static int handle_ffa_ioctl(int fd, unsigned long request, void *argument)
{
	int result = 0;
	int saved_errno = 0;

	if (request == TW_FFA_IOC_MSG_SEND)
		return handle_ffa_message(fd, request, argument);
	if (request == TW_FFA_IOC_SHM_DEINIT)
		return handle_ffa_reclaim(fd, request, argument);
	if (request == TW_FFA_IOC_SHM_INIT) {
		struct tw_ffa_ioctl_shm_desc *description = argument;
		unsigned generation = 0;

		result = real_ioctl_fn(fd, request, argument);
		saved_errno = errno;
		if (result >= 0) {
			generation = register_ffa_handle(description->handle,
						 description->dst_id);
			trace_ffa_lifecycle("ffa_share", description->dst_id,
					    description->handle, generation, NULL, NULL);
		}
		errno = saved_errno;
		return result;
	}
	if (request == TW_FFA_IOC_SHM_READ || request == TW_FFA_IOC_SHM_WRITE) {
		struct tw_ffa_ioctl_buf_desc *description = argument;
		unsigned generation = 0;
		bool live = false;
		uint16_t receiver = 0;

		lookup_ffa_handle(description->handle, &generation, &live, &receiver);
		result = real_ioctl_fn(fd, request, argument);
		saved_errno = errno;
		trace_ffa_raw("ffa_normal_world_access", receiver, -1,
			      description->handle, true, generation, 0, result,
			      result < 0 ? saved_errno : 0, 0,
			      NULL, false);
		errno = saved_errno;
		return result;
	}
	return real_ioctl_fn(fd, request, argument);
}

int ioctl(int fd, unsigned long request, ...)
{
	va_list args;
	void *argument = NULL;
	int result = 0;

	pthread_once(&init_once, initialize);
	va_start(args, request);
	argument = va_arg(args, void *);
	va_end(args);
	if (ffa_trace_enabled && is_ffa_request(request))
		return handle_ffa_ioctl(fd, request, argument);

	if (client_trace_enabled && request == TEE_IOC_INVOKE) {
		struct tee_ioctl_buf_data *data = argument;
		struct tee_ioctl_invoke_arg *invoke =
			(void *)(uintptr_t)data->buf_ptr;
		void *identity = (void *)(uintptr_t)invoke->session;
		int saved_errno = 0;
		uint64_t issue_time = monotonic_ns();

		result = real_ioctl_fn(fd, request, argument);
		saved_errno = errno;
		trace_client_at(issue_time, "operation_issue", identity, identity,
				invoke->func, 0);
		trace_client_at(monotonic_ns(),
				result < 0 || invoke->ret ? "operation_fail" :
				"operation_complete", identity, identity,
				invoke->func,
				result < 0 ? (uint32_t)result : invoke->ret);
		errno = saved_errno;
		return result;
	}

	if (client_trace_enabled && request == TEE_IOC_CANCEL) {
		struct tee_ioctl_cancel_arg *data = argument;
		void *identity = (void *)(uintptr_t)data->session;
		int saved_errno = 0;
		uint64_t cancel_time = monotonic_ns();

		result = real_ioctl_fn(fd, request, argument);
		saved_errno = errno;
		trace_client_at(cancel_time, "operation_cancel", identity, identity,
				0, 0);
		trace_client_at(monotonic_ns(), "cancel_ioctl", identity, identity,
				0, (uint32_t)result);
		errno = saved_errno;
		return result;
	}
	if (!supplicant_process)
		return real_ioctl_fn(fd, request, argument);

	if (request == TEE_IOC_SUPPL_SEND) {
		struct tee_ioctl_buf_data *data = argument;
		struct tee_iocl_supp_send_arg *send =
			(void *)(uintptr_t)data->buf_ptr;
		__u64 *delivered_id = NULL;
		const char *fault_name = apply_send_fault(send);
		uint64_t request_id = current_request;
		uint64_t param_hash = 0;
		int saved_errno = 0;

		if (get_meta_id(send->params, send->num_params, &delivered_id))
			request_id = *delivered_id;
		param_hash = hash_params(send->params, send->num_params);
		/*
		 * Keep the successful SEND and its trace ordered before a worker can
		 * publish a newly received request that reuses the released kernel ID.
		 * RECV itself remains unlocked while blocking.
		 */
		pthread_mutex_lock(&trace_order_mutex);
		result = real_ioctl_fn(fd, request, argument);
		saved_errno = errno;
		trace_rpc("rpc_reply", current_func, request_id,
			  current_request, send->num_params,
			  send->params, param_hash,
			  current_occurrence, fault_name, result);
		pthread_mutex_unlock(&trace_order_mutex);
		errno = saved_errno;
		return result;
	}

	result = real_ioctl_fn(fd, request, argument);
	if (result < 0)
		return result;

	if (request == TEE_IOC_SUPPL_RECV) {
		struct tee_ioctl_buf_data *data = argument;
		struct tee_iocl_supp_recv_arg *recv =
			(void *)(uintptr_t)data->buf_ptr;
		__u64 *request_id = NULL;

		current_func = recv->func;
		pthread_mutex_lock(&state_mutex);
		if (current_func < MAX_TRACKED_FUNC)
			current_occurrence = ++recv_occurrence[current_func];
		else
			current_occurrence = 0;
		pthread_mutex_unlock(&state_mutex);
		current_has_request = get_meta_id(recv->params, recv->num_params,
						  &request_id);
		current_request = current_has_request ? *request_id : trace_sequence + 1;
		pthread_mutex_lock(&trace_order_mutex);
		trace_rpc("rpc_issue", current_func, current_request,
			  current_request, recv->num_params,
			  recv->params, hash_params(recv->params, recv->num_params),
			  current_occurrence, NULL,
			  result);
		pthread_mutex_unlock(&trace_order_mutex);
	} else if (request == TEE_IOC_SHM_ALLOC) {
		struct tee_ioctl_shm_alloc_data *data = argument;
		track_shm_fd(result, data->id, data->size);
	} else if (request == TEE_IOC_SHM_REGISTER) {
		struct tee_ioctl_shm_register_data *data = argument;
		track_shm_fd(result, data->id, data->length);
		/* REGISTER exposes the supplicant-owned userspace buffer directly. */
		track_mapping((void *)(uintptr_t)data->addr, data->length, result);
	}
	return result;
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	void *result = NULL;

	pthread_once(&init_once, initialize);
	result = real_mmap_fn(addr, length, prot, flags, fd, offset);
	if (supplicant_process && result != MAP_FAILED) {
		trace_shm("mmap_observe", fd, 0, length);
		track_mapping(result, length, fd);
	}
	return result;
}

void *mmap64(void *addr, size_t length, int prot, int flags, int fd,
	     off64_t offset)
{
	void *result = NULL;

	pthread_once(&init_once, initialize);
	result = real_mmap64_fn(addr, length, prot, flags, fd, offset);
	if (supplicant_process && result != MAP_FAILED) {
		trace_shm("mmap64_observe", fd, 0, length);
		track_mapping(result, length, fd);
	}
	return result;
}

int munmap(void *addr, size_t length)
{
	int result = 0;
	size_t n = 0;

	pthread_once(&init_once, initialize);
	result = real_munmap_fn(addr, length);
	if (result || !supplicant_process)
		return result;
	pthread_mutex_lock(&state_mutex);
	for (n = 0; n < MAX_TRACKED_MAPPING; n++) {
		if (mapping_records[n].used && mapping_records[n].base == addr) {
			mapping_records[n].used = false;
			break;
		}
	}
	pthread_mutex_unlock(&state_mutex);
	return result;
}

uint32_t TEEC_OpenSession(void *context, void *session, const void *destination,
			 uint32_t connection_method,
			 const void *connection_data, void *operation,
			 uint32_t *return_origin)
{
	uint32_t result = 0;

	pthread_once(&init_once, initialize);
	if (!client_trace_enabled)
		return real_teec_open_session_fn(context, session, destination,
					 connection_method, connection_data,
					 operation, return_origin);
	trace_client("session_open_issue", session, operation, connection_method, 0);
	result = real_teec_open_session_fn(context, session, destination,
					   connection_method, connection_data,
					   operation, return_origin);
	trace_client("session_open_complete", session, operation,
		     connection_method, result);
	return result;
}

void TEEC_CloseSession(void *session)
{
	pthread_once(&init_once, initialize);
	if (!client_trace_enabled) {
		real_teec_close_session_fn(session);
		return;
	}
	trace_client("session_close", session, NULL, 0, 0);
	real_teec_close_session_fn(session);
}

uint32_t TEEC_InvokeCommand(void *session, uint32_t command, void *operation,
			   uint32_t *return_origin)
{
	uint32_t result = 0;

	pthread_once(&init_once, initialize);
	if (!client_trace_enabled)
		return real_teec_invoke_command_fn(session, command, operation,
						   return_origin);
	trace_client("operation_issue", session, operation, command, 0);
	result = real_teec_invoke_command_fn(session, command, operation,
					     return_origin);
	trace_client(result ? "operation_fail" : "operation_complete", session,
		     operation, command, result);
	return result;
}

void TEEC_RequestCancellation(void *operation)
{
	pthread_once(&init_once, initialize);
	if (!client_trace_enabled) {
		real_teec_request_cancellation_fn(operation);
		return;
	}
	trace_client("operation_cancel", NULL, operation, 0, 0);
	real_teec_request_cancellation_fn(operation);
}

int close(int fd)
{
	struct fd_record record = { 0 };

	pthread_once(&init_once, initialize);
	if (!supplicant_process)
		return real_close_fn(fd);
	if (fd >= 0 && fd < MAX_TRACKED_FD) {
		pthread_mutex_lock(&state_mutex);
		record = fd_records[fd];
		fd_records[fd].used = false;
		pthread_mutex_unlock(&state_mutex);
	}
	if (record.used)
		trace_shm("shm_release", record.id, record.generation, 0);
	return real_close_fn(fd);
}
