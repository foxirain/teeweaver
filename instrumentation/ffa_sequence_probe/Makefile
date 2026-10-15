OPTEE_ROOT ?=
ifeq ($(origin CC), default)
ifeq ($(strip $(OPTEE_ROOT)),)
$(error set OPTEE_ROOT to an OP-TEE QEMU build tree, or set CC explicitly)
endif
CC := $(OPTEE_ROOT)/out-br/host/bin/aarch64-linux-gnu-gcc
endif
CFLAGS ?= -O2 -g -Wall -Wextra -Werror

.PHONY: all clean

all: ffa_sequence_probe

ffa_sequence_probe: ffa_sequence_probe.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	$(RM) ffa_sequence_probe
