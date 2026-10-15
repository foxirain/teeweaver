// SPDX-License-Identifier: BSD-3-Clause

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define FFA_DRIVER_PATH "/sys/kernel/debug/arm_ffa_user"
#define FFA_IOC_MAGIC 0xf0
#define FFA_IOC_BASE 0
#define NORMAL_WORLD_ENDPOINT_ID 0
#define MAX_ENDPOINTS 32
#define MAX_HANDLES 64
#define MAX_NAME 32
#define MAX_LINE 512

struct ffa_ioctl_ep_desc {
	uint64_t uuid_ptr;
	uint16_t id;
};

struct ffa_ioctl_msg_args {
	uint64_t args[5];
	uint16_t dst_id;
};

struct ffa_ioctl_shm_desc {
	uint64_t handle;
	uint64_t size;
	uint16_t dst_id;
};

#define FFA_IOC_GET_PART_ID \
	_IOWR(FFA_IOC_MAGIC, FFA_IOC_BASE + 0, struct ffa_ioctl_ep_desc)
#define FFA_IOC_MSG_SEND \
	_IOWR(FFA_IOC_MAGIC, FFA_IOC_BASE + 1, struct ffa_ioctl_msg_args)
#define FFA_IOC_SHM_INIT \
	_IOWR(FFA_IOC_MAGIC, FFA_IOC_BASE + 2, struct ffa_ioctl_shm_desc)
#define FFA_IOC_SHM_DEINIT \
	_IOW(FFA_IOC_MAGIC, FFA_IOC_BASE + 3, struct ffa_ioctl_shm_desc)

struct endpoint_record {
	bool used;
	char name[MAX_NAME];
	uint16_t id;
};

struct handle_record {
	bool used;
	bool live;
	char name[MAX_NAME];
	uint64_t value;
	uint16_t receiver;
};

static struct endpoint_record endpoints[MAX_ENDPOINTS];
static struct handle_record handles[MAX_HANDLES];
static unsigned long step_number;

static struct endpoint_record *find_endpoint(const char *name)
{
	size_t n = 0;

	for (n = 0; n < MAX_ENDPOINTS; n++)
		if (endpoints[n].used && !strcmp(endpoints[n].name, name))
			return &endpoints[n];
	return NULL;
}

static struct handle_record *find_handle(const char *name)
{
	size_t n = 0;

	for (n = 0; n < MAX_HANDLES; n++)
		if (handles[n].used && !strcmp(handles[n].name, name))
			return &handles[n];
	return NULL;
}

static int add_endpoint(int fd, const char *name, const char *uuid)
{
	struct ffa_ioctl_ep_desc descriptor = {
		.uuid_ptr = (uint64_t)(uintptr_t)uuid,
	};
	size_t n = 0;

	if (strlen(name) >= MAX_NAME || find_endpoint(name))
		return -1;
	if (ioctl(fd, FFA_IOC_GET_PART_ID, &descriptor))
		return -1;
	for (n = 0; n < MAX_ENDPOINTS; n++) {
		if (endpoints[n].used)
			continue;
		endpoints[n].used = true;
		strcpy(endpoints[n].name, name);
		endpoints[n].id = descriptor.id;
		printf("{\"step\":%lu,\"op\":\"resolve\",\"name\":\"%s\","
		       "\"endpoint\":%u}\n", ++step_number, name, descriptor.id);
		fflush(stdout);
		return 0;
	}
	errno = ENOSPC;
	return -1;
}

static int send_action(int fd, const struct endpoint_record *endpoint,
		       unsigned long action, const struct handle_record *handle)
{
	struct ffa_ioctl_msg_args message = { 0 };
	int saved_errno = 0;
	int rc = 0;

	message.dst_id = endpoint->id;
	message.args[0] = action;
	if (handle) {
		message.args[1] = handle->value & UINT64_C(0xffffffff);
		message.args[2] = handle->value >> 32;
		message.args[3] = NORMAL_WORLD_ENDPOINT_ID;
	}
	errno = 0;
	rc = ioctl(fd, FFA_IOC_MSG_SEND, &message);
	saved_errno = rc < 0 ? errno : 0;
	printf("{\"step\":%lu,\"op\":\"send\",\"endpoint_name\":\"%s\","
	       "\"endpoint\":%u,\"action\":%lu,\"handle_name\":\"%s\","
	       "\"handle\":\"%016" PRIx64 "\",\"rc\":%d,\"errno\":%d,"
	       "\"response\":\"%016" PRIx64 "\"}\n",
	       ++step_number, endpoint->name, endpoint->id, action,
	       handle ? handle->name : "", handle ? handle->value : 0,
	       rc, saved_errno, message.args[0]);
	fflush(stdout);
	return rc;
}

static int share_memory(int fd, const char *name,
			const struct endpoint_record *endpoint, uint64_t size)
{
	struct ffa_ioctl_shm_desc memory = {
		.size = size,
		.dst_id = endpoint->id,
	};
	size_t n = 0;
	int saved_errno = 0;
	int rc = 0;

	if (strlen(name) >= MAX_NAME || find_handle(name)) {
		errno = EEXIST;
		return -1;
	}
	errno = 0;
	rc = ioctl(fd, FFA_IOC_SHM_INIT, &memory);
	saved_errno = rc < 0 ? errno : 0;
	printf("{\"step\":%lu,\"op\":\"share\",\"handle_name\":\"%s\","
	       "\"endpoint\":%u,\"size\":%" PRIu64 ","
	       "\"handle\":\"%016" PRIx64 "\",\"rc\":%d,\"errno\":%d}\n",
	       ++step_number, name, endpoint->id, size, memory.handle, rc,
	       saved_errno);
	fflush(stdout);
	if (rc < 0)
		return rc;
	for (n = 0; n < MAX_HANDLES; n++) {
		if (handles[n].used)
			continue;
		handles[n].used = true;
		handles[n].live = true;
		strcpy(handles[n].name, name);
		handles[n].value = memory.handle;
		handles[n].receiver = endpoint->id;
		return 0;
	}
	errno = ENOSPC;
	return -1;
}

static int reclaim_memory(int fd, struct handle_record *handle)
{
	struct ffa_ioctl_shm_desc memory = {
		.handle = handle->value,
		.dst_id = handle->receiver,
	};
	int saved_errno = 0;
	int rc = 0;

	errno = 0;
	rc = ioctl(fd, FFA_IOC_SHM_DEINIT, &memory);
	saved_errno = rc < 0 ? errno : 0;
	if (!rc)
		handle->live = false;
	printf("{\"step\":%lu,\"op\":\"reclaim\",\"handle_name\":\"%s\","
	       "\"handle\":\"%016" PRIx64 "\",\"rc\":%d,\"errno\":%d}\n",
	       ++step_number, handle->name, handle->value, rc, saved_errno);
	fflush(stdout);
	return rc;
}

static char *next_token(char **save)
{
	return strtok_r(NULL, " \t\r\n", save);
}

static int execute_line(int fd, char *line, unsigned long line_number)
{
	char *save = NULL;
	char *command = strtok_r(line, " \t\r\n", &save);
	char *a = NULL;
	char *b = NULL;
	char *c = NULL;
	char *end = NULL;
	unsigned long value = 0;
	struct endpoint_record *endpoint = NULL;
	struct handle_record *handle = NULL;

	if (!command || command[0] == '#')
		return 0;
	if (!strcmp(command, "endpoint")) {
		a = next_token(&save);
		b = next_token(&save);
		if (!a || !b || next_token(&save) || add_endpoint(fd, a, b))
			goto invalid;
		return 0;
	}
	if (!strcmp(command, "ping")) {
		a = next_token(&save);
		endpoint = a ? find_endpoint(a) : NULL;
		if (!endpoint || next_token(&save))
			goto invalid;
		(void)send_action(fd, endpoint, 0, NULL);
		return 0;
	}
	if (!strcmp(command, "share")) {
		a = next_token(&save);
		b = next_token(&save);
		c = next_token(&save);
		endpoint = b ? find_endpoint(b) : NULL;
		value = c ? strtoul(c, &end, 0) : 0x1000;
		if (!a || !endpoint || (c && (!end || *end)) || !value ||
		    next_token(&save) || share_memory(fd, a, endpoint, value))
			goto invalid;
		return 0;
	}
	if (!strcmp(command, "send")) {
		a = next_token(&save);
		b = next_token(&save);
		c = next_token(&save);
		endpoint = a ? find_endpoint(a) : NULL;
		value = b ? strtoul(b, &end, 0) : 0;
		handle = c ? find_handle(c) : NULL;
		if (!endpoint || !b || !end || *end || (c && !handle) ||
		    next_token(&save))
			goto invalid;
		(void)send_action(fd, endpoint, value, handle);
		return 0;
	}
	if (!strcmp(command, "reclaim")) {
		a = next_token(&save);
		handle = a ? find_handle(a) : NULL;
		if (!handle || next_token(&save))
			goto invalid;
		(void)reclaim_memory(fd, handle);
		return 0;
	}
	if (!strcmp(command, "sleep")) {
		a = next_token(&save);
		value = a ? strtoul(a, &end, 0) : 0;
		if (!a || !end || *end || next_token(&save))
			goto invalid;
		usleep(value);
		printf("{\"step\":%lu,\"op\":\"sleep\",\"microseconds\":%lu}\n",
		       ++step_number, value);
		fflush(stdout);
		return 0;
	}
invalid:
	fprintf(stderr, "invalid plan line %lu: %s (errno=%d)\n",
		line_number, command ? command : "<empty>", errno);
	return -1;
}

int main(int argc, char **argv)
{
	char line[MAX_LINE];
	unsigned long line_number = 0;
	FILE *plan = NULL;
	int fd = -1;

	if (argc != 2) {
		fprintf(stderr, "usage: %s PLAN\n", argv[0]);
		return 2;
	}
	plan = fopen(argv[1], "r");
	if (!plan) {
		perror("open plan");
		return 1;
	}
	fd = open(FFA_DRIVER_PATH, O_RDWR);
	if (fd < 0) {
		perror("open arm_ffa_user");
		fclose(plan);
		return 1;
	}
	while (fgets(line, sizeof(line), plan)) {
		line_number++;
		if (!strchr(line, '\n') && !feof(plan)) {
			fprintf(stderr, "plan line %lu exceeds %u bytes\n",
				line_number, MAX_LINE - 1);
			close(fd);
			fclose(plan);
			return 2;
		}
		if (execute_line(fd, line, line_number)) {
			close(fd);
			fclose(plan);
			return 2;
		}
	}
	close(fd);
	fclose(plan);
	return 0;
}
