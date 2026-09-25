OPTEE_ROOT ?= $(abspath $(CURDIR)/../../../optee-qemu-v8)
ifeq ($(origin CC), default)
CC := $(OPTEE_ROOT)/out-br/host/bin/aarch64-linux-gnu-gcc
endif
CFLAGS ?= -O2 -g -fPIC -Wall -Wextra -Werror
LDFLAGS ?= -shared
LDLIBS ?= -ldl -pthread
HOSTCC ?= cc

.PHONY: all clean test-host

all: libteeweaver.so

libteeweaver.so: teeweaver_preload.c exports-aarch64.map
	$(CC) $(CFLAGS) $(LDFLAGS) \
		-Wl,--version-script=exports-aarch64.map -o $@ $< $(LDLIBS)

clean:
	$(RM) libteeweaver.so host-libteeweaver.so test_driver

host-libteeweaver.so: teeweaver_preload.c
	$(HOSTCC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

test_driver: test_driver.c
	$(HOSTCC) -O2 -g -Wall -Wextra -Werror -pthread -o $@ $<

test-host: host-libteeweaver.so test_driver
	$(RM) /tmp/teeweaver-preload-test.jsonl
	TEEWEAVER_TRACE=/tmp/teeweaver-preload-test.jsonl \
	TEEWEAVER_ROLE=supplicant \
	TEEWEAVER_FAULT=swap_pair:0 \
	LD_PRELOAD=$(CURDIR)/host-libteeweaver.so ./test_driver
	test "$$(wc -l < /tmp/teeweaver-preload-test.jsonl)" -eq 2
	grep -q '\"fault\":\"swap-pair\"' /tmp/teeweaver-preload-test.jsonl
