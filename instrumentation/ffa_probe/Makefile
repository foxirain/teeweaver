OPTEE_ROOT ?= $(abspath $(CURDIR)/../../../optee-qemu-v8)
ifeq ($(origin CC), default)
CC := $(OPTEE_ROOT)/out-br/host/bin/aarch64-linux-gnu-gcc
endif
CFLAGS ?= -O2 -g -Wall -Wextra -Werror

.PHONY: all clean

all: ffa_probe

ffa_probe: ffa_probe.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	$(RM) ffa_probe
