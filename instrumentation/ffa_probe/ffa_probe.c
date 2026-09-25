// SPDX-License-Identifier: BSD-3-Clause

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define FFA_DRIVER_PATH "/sys/kernel/debug/arm_ffa_user"
#define FFA_IOC_MAGIC 0xf0
#define FFA_IOC_BASE 0
#define SPMC_TEST_OK UINT64_C(0xaa)
#define NORMAL_WORLD_ENDPOINT_ID 0

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

enum sp_test {
	EP_TEST_SP = 0,
	EP_TRY_R_ACCESS = 3,
	EP_RETRIEVE = 5,
	EP_RELINQUISH = 6,
};

static int send_action(int fd, uint16_t endpoint, enum sp_test action,
		       uint64_t handle, uint64_t *response)
{
	struct ffa_ioctl_msg_args args = { 0 };
	unsigned attempt = 0;
	int rc = 0;

	for (attempt = 0; attempt < 5000; attempt++) {
		memset(&args, 0, sizeof(args));
		args.dst_id = endpoint;
		args.args[0] = action;
		if (action == EP_RETRIEVE || action == EP_RELINQUISH) {
			args.args[1] = handle & UINT64_C(0xffffffff);
			args.args[2] = handle >> 32;
			args.args[3] = NORMAL_WORLD_ENDPOINT_ID;
		}
		rc = ioctl(fd, FFA_IOC_MSG_SEND, &args);
		if (!rc || (errno != EBUSY && errno != EAGAIN))
			break;
		usleep(1000);
	}
	*response = args.args[0];
	return rc;
}

static int expect_sp_ok(int fd, uint16_t endpoint, enum sp_test action,
			uint64_t handle, const char *step)
{
	uint64_t response = 0;
	int rc = send_action(fd, endpoint, action, handle, &response);

	if (rc || response != SPMC_TEST_OK) {
		fprintf(stderr, "%s failed: ioctl=%d errno=%d response=%" PRIu64 "\n",
			step, rc, errno, response);
		return -1;
	}
	return 0;
}

static int run_lifecycle(int fd, uint16_t endpoint, unsigned cycle)
{
	struct ffa_ioctl_shm_desc memory = {
		.size = 0x1000,
		.dst_id = endpoint,
	};
	uint64_t response = 0;
	int rc = 0;

	if (expect_sp_ok(fd, endpoint, EP_TEST_SP, 0, "ping"))
		return -1;
	if (ioctl(fd, FFA_IOC_SHM_INIT, &memory)) {
		perror("share");
		return -1;
	}
	if (expect_sp_ok(fd, endpoint, EP_RETRIEVE, memory.handle, "retrieve-1") ||
	    expect_sp_ok(fd, endpoint, EP_RETRIEVE, memory.handle, "retrieve-2") ||
	    expect_sp_ok(fd, endpoint, EP_TRY_R_ACCESS, 0, "read") ||
	    expect_sp_ok(fd, endpoint, EP_RELINQUISH, memory.handle,
			 "relinquish-1"))
		return -1;

	errno = 0;
	rc = ioctl(fd, FFA_IOC_SHM_DEINIT, &memory);
	if (rc >= 0) {
		fprintf(stderr, "early reclaim unexpectedly succeeded\n");
		return -1;
	}
	if (expect_sp_ok(fd, endpoint, EP_RELINQUISH, memory.handle,
			 "relinquish-2"))
		return -1;
	if (ioctl(fd, FFA_IOC_SHM_DEINIT, &memory)) {
		perror("balanced reclaim");
		return -1;
	}

	rc = send_action(fd, endpoint, EP_RETRIEVE, memory.handle, &response);
	if (rc || response == SPMC_TEST_OK) {
		fprintf(stderr,
			"stale retrieve was not rejected: ioctl=%d response=%" PRIu64 "\n",
			rc, response);
		return -1;
	}
	printf("cycle=%u endpoint=%u handle=%016" PRIx64 " ok\n",
	       cycle, endpoint, memory.handle);
	return 0;
}

int main(int argc, char **argv)
{
	struct ffa_ioctl_ep_desc endpoint = { 0 };
	unsigned long loops = 1;
	char *end = NULL;
	int fd = -1;
	unsigned long n = 0;

	if (argc < 2 || argc > 3) {
		fprintf(stderr, "usage: %s UUID [LOOPS]\n", argv[0]);
		return 2;
	}
	if (argc == 3) {
		loops = strtoul(argv[2], &end, 0);
		if (!loops || !end || *end) {
			fprintf(stderr, "invalid loop count\n");
			return 2;
		}
	}
	fd = open(FFA_DRIVER_PATH, O_RDWR);
	if (fd < 0) {
		perror("open arm_ffa_user");
		return 1;
	}
	endpoint.uuid_ptr = (uint64_t)(uintptr_t)argv[1];
	if (ioctl(fd, FFA_IOC_GET_PART_ID, &endpoint)) {
		perror("resolve endpoint");
		close(fd);
		return 1;
	}
	for (n = 1; n <= loops; n++) {
		if (run_lifecycle(fd, endpoint.id, (unsigned)n)) {
			close(fd);
			return 1;
		}
	}
	close(fd);
	return 0;
}
