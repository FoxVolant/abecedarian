#include "libbpf/include/uapi/linux/bpf.h"
//#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/types.h>

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define O_NONBLOCK	00004000
#define PATHLEN 256
#define MAXFILESIZE 0x20000000
#define MAY_WRITE 0x00000002
#define MAY_READ 0x00000004


typedef unsigned int gfp_t;
#ifdef CONFIG_64BIT
# define DNAME_INLINE_LEN 32 /* 192 bytes */
#else
# ifdef CONFIG_SMP
#  define DNAME_INLINE_LEN 36 /* 128 bytes */
# else
#  define DNAME_INLINE_LEN 40 /* 128 bytes */
# endif
#endif
///*
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} lru_hash SEC(".maps");

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

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12);
} ringbuf SEC(".maps");

struct output {
	__u32 pid;
	__u32 tgid;
	char buf[PATHLEN];
};


//*/

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



struct qstr {
	const unsigned char *name;

} __attribute__((preserve_access_index));

struct dentry{
	struct qstr d_name;
	unsigned char d_iname[DNAME_INLINE_LEN];	/* small names */
} __attribute__((preserve_access_index));


struct path{
	struct dentry *dentry;

} __attribute__((preserve_access_index));

struct inode {
	long long			i_size;
} __attribute__((preserve_access_index));


struct file {
	const struct cred	*f_cred;
	unsigned int 		f_flags; 
	struct path             f_path;	
	struct inode		*f_inode;

} __attribute__((preserve_access_index));

struct fdtable {
	struct file  **fd;      /* current fd array */
} __attribute__((preserve_access_index));

struct files_struct {
	struct fdtable  *fdt;
	struct fdtable fdtab;
} __attribute__((preserve_access_index));

struct task_struct {
    unsigned int flags;
    const struct cred *cred;
    struct file_struct		*files;
} __attribute__((preserve_access_index));


struct mm_struct{
		unsigned long start_brk, brk, start_stack;
		unsigned long arg_start;
} __attribute__((preserve_access_index));

struct vm_area_struct{

	unsigned long vm_start;
	unsigned long vm_end;
	struct mm_struct *vm_mm;
} __attribute__((preserve_access_index));

struct linux_binprm {
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	int argc;
        struct file *file;
} __attribute__((preserve_access_index));



static int strcmp_64(char *s1, char *s2){
    int i;
    #pragma clang loop unroll(full)
    for(i=63;i>0;i--){
        if(s1[i] != s2[i])
            break;
    }
    return i;
}
char LICENSE[] SEC("license") = "GPL";

SEC("lsm/bprm_check_security")
int BPF_PROG(handler_bprm_check, struct linux_binprm *bprm)
{
        if (bprm->argc == 0) {
          //      log_process_name(bprm);
                return -EINVAL;
        }
        return 0;
}

SEC("lsm/bprm_creds_from_file")
int BPF_PROG(handler_bprm_creds_from_file, struct linux_binprm *bprm, struct file *file)
{


	return 0;
}
int monitored_pid = 0;
int mprotect_count = 0;
int bprm_count = 0;
	
SEC("lsm/file_mprotect")
int BPF_PROG(handler_file_mprotect,  struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot, int ret)
{
	if (ret != 0)
		return ret;

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	int is_stack = 0;

	is_stack = (vma->vm_start <= vma->vm_mm->start_stack &&  vma->vm_end >= vma->vm_mm->start_stack);

	if (is_stack  && monitored_pid == pid ) {
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

SEC("lsm/task_free") /* lsm/ is ok, lsm.s/ fails */
int BPF_PROG(test_task_free, struct task_struct *task)
{
	return 0;
}

/*
int copy_test = 0;

SEC("fentry.s/__x64_sys_setdomainname")
int BPF_PROG(test_sys_setdomainname, struct pt_regs *regs)
{
	void *ptr = (void *)PT_REGS_PARM1(regs);
	int len = PT_REGS_PARM2(regs);
	int buf = 0;
	long ret;

	ret = bpf_copy_from_user(&buf, sizeof(buf), ptr);
	if (len == -2 && ret == 0 && buf == 1234)
		copy_test++;
	if (len == -3 && ret == -EFAULT)
		copy_test++;
	if (len == -4 && ret == -EFAULT)
		copy_test++;
	return 0;
}
*/
SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *now, int ret)
{

    	struct task_struct *task;
	struct files_struct *files = NULL;
	struct file *fd = NULL;

	struct fdtable *fdt = NULL;
        char *filename = NULL;

	const char fmt_str[] = "hello world,my pid is %d\n";
      	if (ret) {
        	return ret;
    	}



        task = bpf_get_current_task_btf();
	int pid = bpf_get_current_pid_tgid() >>32;
//	files = task->files;
//	fdt = files->fdt;

//	fd = fdt->fd;

	//filename = fd->f_path.dentry->d_iname;
	
//	filename = now->f_path.dentry->d_iname;
//	bpf_trace_printk(fmt_str, sizeof(fmt_str), pid);
//	bpf_trace_printk(filename,sizeof(filename),pid);
//	bpf_printk("%s", &filename);
/*	if(strcmp_64((char *)filename , "passwd") )
        {
                return -EPERM;
        }
*/	if(now->f_flags)
	{
		return -EPERM;
	}



	return 0;
}

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

   // bpfprint("hook to  cred_prepare");
    // Allow tasks with CAP_SYS_ADMIN to unshare (already root)
    if (caps.cap[CAP_TO_INDEX(CAP_SYS_ADMIN)] & CAP_TO_MASK(CAP_SYS_ADMIN)) {
        return -EPERM;
    }

    //deny the active for cap up
    if(&new->cap_effective == &old->cap_effective){
    
    return -EPERM;
    }

    return 0;
}

