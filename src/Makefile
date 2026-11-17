# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
CLANG   ?= clang
CC      ?= gcc
BPFTOOL ?= $(shell command -v bpftool 2>/dev/null || echo /usr/sbin/bpftool)

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BTF_VMLINUX ?= /sys/kernel/btf/vmlinux
VMLINUX_H   := ebpf/vmlinux.h
BPF_SRC     := ebpf/pqc_trace.bpf.c
BPF_HDR     := ebpf/pqc_trace.h
BPF_OBJ     := ebpf/pqc_trace.bpf.o
BPF_SKEL    := ebpf/pqc_trace.skel.h

USER_SRC    := collector/loader.c
TARGET      := loader

BPF_CFLAGS  := -g -O2 -Wall -Wextra -target bpf -D__TARGET_ARCH_$(ARCH) -Iebpf
USER_CFLAGS := -g -O2 -Wall -Wextra -Iebpf
USER_LDLIBS := -lbpf -lelf -lz -lm

.PHONY: all clean

all: $(TARGET)

$(VMLINUX_H): $(BTF_VMLINUX)
	$(BPFTOOL) btf dump file $(BTF_VMLINUX) format c > $@

$(BPF_OBJ): $(BPF_SRC) $(BPF_HDR) $(VMLINUX_H)
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $@

$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(TARGET): $(USER_SRC) $(BPF_HDR) $(BPF_SKEL)
	$(CC) $(USER_CFLAGS) $(USER_SRC) -o $@ $(USER_LDLIBS)
	ln -sf ../$(TARGET) collector/loader

clean:
	rm -f $(TARGET) collector/loader $(BPF_OBJ) $(BPF_SKEL) $(VMLINUX_H)

