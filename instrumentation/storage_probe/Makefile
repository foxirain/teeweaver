OPTEE_ROOT ?= $(abspath $(CURDIR)/../../../optee-qemu-v8)
ifeq ($(origin CC), default)
CC := $(OPTEE_ROOT)/out-br/host/bin/aarch64-linux-gnu-gcc
endif
SYSROOT := $(OPTEE_ROOT)/out-br/host/aarch64-buildroot-linux-gnu/sysroot
CFLAGS ?= -O2 -g -Wall -Wextra -Werror
CPPFLAGS += -I$(OPTEE_ROOT)/optee_client/libteec/include
CPPFLAGS += -I$(OPTEE_ROOT)/optee_test/ta/include
CPPFLAGS += -I$(OPTEE_ROOT)/optee_os/lib/libutee/include
LDFLAGS += --sysroot=$(SYSROOT)
LDLIBS += -lteec

.PHONY: all clean

all: storage_probe

storage_probe: storage_probe.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	$(RM) storage_probe
