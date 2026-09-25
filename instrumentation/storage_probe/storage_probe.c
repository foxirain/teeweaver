#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tee_client_api.h>
#include <tee_api_defines.h>
#include <ta_storage.h>

static const TEEC_UUID storage_uuid = TA_STORAGE_UUID;
static const uint8_t object_id[] = "teeweaver-reset-token-v1";

static void fail(const char *where, TEEC_Result result, uint32_t origin)
{
	fprintf(stderr, "%s failed: result=0x%08x origin=0x%08x\n",
		where, result, origin);
	exit(1);
}

static TEEC_Result create_value(TEEC_Session *session, const void *data,
				 size_t size, uint32_t *origin)
{
	TEEC_Operation operation = { 0 };

	operation.params[0].tmpref.buffer = (void *)object_id;
	operation.params[0].tmpref.size = sizeof(object_id);
	operation.params[1].value.a = TEE_DATA_FLAG_ACCESS_READ |
		TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_WRITE_META |
		TEE_DATA_FLAG_OVERWRITE;
	operation.params[2].value.a = 0;
	operation.params[2].value.b = TEE_STORAGE_PRIVATE;
	operation.params[3].tmpref.buffer = (void *)data;
	operation.params[3].tmpref.size = size;
	operation.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INOUT,
		TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT);
	return TEEC_InvokeCommand(session, TA_STORAGE_CMD_CREATE, &operation,
				  origin);
}

static TEEC_Result open_value(TEEC_Session *session, uint32_t *handle,
			      uint32_t *origin)
{
	TEEC_Operation operation = { 0 };
	TEEC_Result result = TEEC_ERROR_GENERIC;

	operation.params[0].tmpref.buffer = (void *)object_id;
	operation.params[0].tmpref.size = sizeof(object_id);
	operation.params[1].value.a = TEE_DATA_FLAG_ACCESS_READ |
		TEE_DATA_FLAG_ACCESS_WRITE_META;
	operation.params[2].value.a = TEE_STORAGE_PRIVATE;
	operation.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INOUT,
		TEEC_VALUE_INPUT, TEEC_NONE);
	result = TEEC_InvokeCommand(session, TA_STORAGE_CMD_OPEN, &operation,
				    origin);
	if (result == TEEC_SUCCESS)
		*handle = operation.params[1].value.b;
	return result;
}

static TEEC_Result read_value(TEEC_Session *session, uint32_t handle,
			      uint8_t *buffer, size_t size, size_t *actual,
			      uint32_t *origin)
{
	TEEC_Operation operation = { 0 };
	TEEC_Result result = TEEC_ERROR_GENERIC;

	operation.params[0].tmpref.buffer = buffer;
	operation.params[0].tmpref.size = size;
	operation.params[1].value.a = handle;
	operation.params[1].value.b = size;
	operation.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
	result = TEEC_InvokeCommand(session, TA_STORAGE_CMD_READ, &operation,
				    origin);
	if (result == TEEC_SUCCESS)
		*actual = operation.params[1].value.b;
	return result;
}

static void close_value(TEEC_Session *session, uint32_t handle,
			uint32_t *origin)
{
	TEEC_Operation operation = { 0 };
	TEEC_Result result = TEEC_ERROR_GENERIC;

	operation.params[0].value.a = handle;
	operation.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	result = TEEC_InvokeCommand(session, TA_STORAGE_CMD_CLOSE, &operation,
				    origin);
	if (result != TEEC_SUCCESS)
		fail("close", result, *origin);
}

static void print_hex(const uint8_t *data, size_t size)
{
	size_t n = 0;

	for (n = 0; n < size; n++)
		printf("%02x", data[n]);
}

int main(int argc, char **argv)
{
	TEEC_Context context = { 0 };
	TEEC_Session session = { 0 };
	TEEC_Result result = TEEC_ERROR_GENERIC;
	uint32_t origin = 0;
	uint32_t handle = 0;
	uint8_t output[512] = { 0 };
	size_t actual = 0;

	if (argc < 2 || (strcmp(argv[1], "write") && strcmp(argv[1], "read"))) {
		fprintf(stderr, "usage: %s write VALUE | read\n", argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "write") && argc != 3) {
		fprintf(stderr, "write requires one value\n");
		return 2;
	}
	result = TEEC_InitializeContext(NULL, &context);
	if (result != TEEC_SUCCESS)
		fail("initialize", result, 0);
	result = TEEC_OpenSession(&context, &session, &storage_uuid,
				  TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (result != TEEC_SUCCESS)
		fail("open-session", result, origin);

	if (!strcmp(argv[1], "write")) {
		result = create_value(&session, argv[2], strlen(argv[2]), &origin);
		if (result != TEEC_SUCCESS)
			fail("write", result, origin);
		printf("TEEWEAVER_STORAGE_ACK value_hex=");
		print_hex((const uint8_t *)argv[2], strlen(argv[2]));
		printf("\n");
	} else {
		result = open_value(&session, &handle, &origin);
		if (result != TEEC_SUCCESS)
			fail("open", result, origin);
		result = read_value(&session, handle, output, sizeof(output),
				    &actual, &origin);
		if (result != TEEC_SUCCESS)
			fail("read", result, origin);
		printf("TEEWEAVER_STORAGE_OBSERVE value_hex=");
		print_hex(output, actual);
		printf("\n");
		close_value(&session, handle, &origin);
	}

	TEEC_CloseSession(&session);
	TEEC_FinalizeContext(&context);
	return 0;
}
