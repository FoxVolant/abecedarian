CLANG ?= clang-10
LLVM_STRIP ?= llvm-strip-12
ARCH := x86
INCLUDES := -I/usr/include -I/usr/include/x86_64-linux-gnu -I/home/shi/linux-5.15.41/tools/lib -I/home/shi/linux-5.15.41/tools/lib/bpf  -I/home/shi/work/lsm_bpf/libbpf/src -I/home/shi/linux-5.15.41/tools


LIBS_DIR := -L/usr/lib/lib64 -L/usr/lib/x86_64-linux-gnu
LIBS := -lbpf -lelf

.PHONY: all clean run

all: lsm_bpf.skel.h lsm_bpf.o lsm_bpf

run: all
	sudo ./lsm_bpf

clean:
	rm -f *.o
	rm -f lsm_bpf.skel.h

#
# BPF is kernel code. We need to pass -D__KERNEL__ to refer to fields present
# in the kernel version of pt_regs struct. uAPI version of pt_regs (from ptrace)
# has different field naming.
#
lsm_bpf.o: lsm_bpf.c
	$(CLANG) -g -O2 -Wall -target bpf -D__KERNEL__ -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $< -o $@
	$(LLVM_STRIP) -g $@ # Removes debug information

lsm_bpf.skel.h: lsm_bpf.o
	sudo bpftool gen skeleton $< > $@

lsm_bpf: lsm_bpf.c lsm_bpf.skel.h
	$(CC) -g -Wall -c $< -o $@.o
	$(CC) -g -o $@ $(LIBS_DIR) $@.o $(LIBS)

.DELETE_ON_ERROR:
