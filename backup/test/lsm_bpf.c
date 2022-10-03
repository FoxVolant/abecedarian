#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/types.h>

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define X86_64_UNSHARE_SYSCALL 272
#define UNSHARE_SYSCALL X86_64_UNSHARE_SYSCALL

typedef unsigned int gfp_t;

struct pt_regs {
        long unsigned int di;
        long unsigned int orig_ax;
} __attribute__((preserve_access_index));

typedef struct kernel_cap_struct {
        __u32 cap[_LINUX_CAPABILITY_U32S_3];
} __attribute__((preserve_access_index)) kernel_cap_t;


struct cred {
        kernel_cap_t cap_effective;
} __attribute__((preserve_access_index));


struct task_struct {
    unsigned int flags;
    const struct cred *cred;
}__attribute__((preserve_access_index));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
}array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
}hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
}lru_hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} percpu_array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} percpu_hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} lru_percpu_hash SEC(".maps");

struct inner_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, __u64);
} inner_map SEC(".maps");

struct outer_arr {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__array(values, struct inner_map);
} outer_arr SEC(".maps") = {
	.values = { [0] = &inner_map },
};

struct outer_hash {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(int));
	__array(values, struct inner_map);
} outer_hash SEC(".maps") = {
	.values = { [0] = &inner_map },
};

char LICENSE[] SEC("license") = "GPL";

/*
SEC("lsm/file_mprotect")
int BPF_PROG(test_int_hook, struct vm_area_struct *vma,
	     unsigned long reqprot, unsigned long prot, int ret)
{
	if (ret != 0)
		return ret;

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	int is_stack = 0;

	is_stack = (vma->vm_start <= vma->vm_mm->start_stack &&
		    vma->vm_end >= vma->vm_mm->start_stack);

	if (is_stack && monitored_pid == pid) {
		mprotect_count++;
		ret = -EPERM;
	}

	return ret;
}

SEC("lsm.s/bprm_committed_creds")
int BPF_PROG(test_void_hook, struct linux_binprm *bprm)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct inner_map *inner_map;
	char args[64];
	__u32 key = 0;
	__u64 *value;

	if (monitored_pid == pid)
		bprm_count++;

	bpf_copy_from_user(args, sizeof(args), (void *)bprm->vma->vm_mm->arg_start);
	bpf_copy_from_user(args, sizeof(args), (void *)bprm->mm->arg_start);

	value = bpf_map_lookup_elem(&array, &key);
	if (value)
		*value = 0;
	value = bpf_map_lookup_elem(&hash, &key);
	if (value)
		*value = 0;
	value = bpf_map_lookup_elem(&lru_hash, &key);
	if (value)
		*value = 0;
	value = bpf_map_lookup_elem(&percpu_array, &key);
	if (value)
		*value = 0;
	value = bpf_map_lookup_elem(&percpu_hash, &key);
	if (value)
		*value = 0;
	value = bpf_map_lookup_elem(&lru_percpu_hash, &key);
	if (value)
		*value = 0;
	inner_map = bpf_map_lookup_elem(&outer_arr, &key);
	if (inner_map) {
		value = bpf_map_lookup_elem(inner_map, &key);
		if (value)
			*value = 0;
	}
	inner_map = bpf_map_lookup_elem(&outer_hash, &key);
	if (inner_map) {
		value = bpf_map_lookup_elem(inner_map, &key);
		if (value)
			*value = 0;
	}

	return 0;
}
*/
SEC("lsm/cred_prepare")
int BPF_PROG(handle_cred_prepare, struct cred *new, const struct cred *old,
             gfp_t gfp, int ret)
{
    struct pt_regs *regs;
    struct task_struct *task;
    kernel_cap_t caps;
    int syscall;
    unsigned long flags;

    // If previous hooks already denied, go ahead and deny this one
    if (ret) {
        return ret;
    }

    task = bpf_get_current_task_btf();
    regs = (struct pt_regs *) bpf_task_pt_regs(task);
    // In x86_64 orig_ax has the syscall interrupt stored here
    syscall = regs->orig_ax;
    caps = task->cred->cap_effective;

    // Only process UNSHARE syscall, ignore all others
    if (syscall != UNSHARE_SYSCALL) {
        return 0;
    }

    // PT_REGS_PARM1_CORE pulls the first parameter passed into the unshare syscall
    flags = PT_REGS_PARM1_CORE(regs);

    // Ignore any unshare that does not have CLONE_NEWUSER
    if (!(flags & CLONE_NEWUSER)) {
        return 0;
    }

    // Allow tasks with CAP_SYS_ADMIN to unshare (already root)
    if (caps.cap[CAP_TO_INDEX(CAP_SYS_ADMIN)] & CAP_TO_MASK(CAP_SYS_ADMIN)) {
        return 0;
    }

    return -EPERM;
}

