#include <errno.h>
#include <linux/tee.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct response {
	struct tee_iocl_supp_send_arg send;
	struct tee_ioctl_param params[1];
};

struct worker {
	struct response response;
	uint64_t original_id;
};

static void *send_response(void *argument)
{
	struct worker *worker = argument;
	struct tee_ioctl_buf_data data = {
		.buf_ptr = (uintptr_t)&worker->response,
		.buf_len = sizeof(worker->response),
	};

	/* EBADF is expected: the preload layer is the component under test. */
	if (ioctl(-1, TEE_IOC_SUPPL_SEND, &data) != -1 || errno != EBADF)
		return (void *)1;
	return NULL;
}

int main(void)
{
	struct worker workers[2];
	pthread_t threads[2];
	void *result = NULL;
	int n = 0;

	memset(workers, 0, sizeof(workers));
	workers[0].original_id = 101;
	workers[1].original_id = 202;
	for (n = 0; n < 2; n++) {
		workers[n].response.send.num_params = 1;
		workers[n].response.params[0].attr =
			TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT |
			TEE_IOCTL_PARAM_ATTR_META;
		workers[n].response.params[0].a = workers[n].original_id;
	}

	if (pthread_create(&threads[0], NULL, send_response, &workers[0]))
		return 2;
	usleep(50000);
	if (pthread_create(&threads[1], NULL, send_response, &workers[1]))
		return 3;
	for (n = 0; n < 2; n++) {
		if (pthread_join(threads[n], &result) || result)
			return 4;
	}
	if (workers[0].response.params[0].a != workers[1].original_id ||
	    workers[1].response.params[0].a != workers[0].original_id) {
		fprintf(stderr, "request IDs were not exchanged\n");
		return 5;
	}
	puts("swap_pair interposer test passed");
	return 0;
}
