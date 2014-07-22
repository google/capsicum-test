/* seccomp-BPF implementation of capability mode */
#ifdef __linux__
#define _GNU_SOURCE  /* to get O_* constants */
#include <errno.h>
#include <stddef.h>
#include <fcntl.h>
#include <stdio.h>
#include <syscall.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/unistd.h>
#include <asm/prctl.h>

/* Macros for BPF generation */
#if defined(__i386__)
#define ARCH_NR	AUDIT_ARCH_I386
#elif defined(__x86_64__)
#define ARCH_NR	AUDIT_ARCH_X86_64
#else
#warning "Platform does not support seccomp filter yet"
#define ARCH_NR	0
#endif

#define VALIDATE_ARCHITECTURE	\
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),	\
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0),	\
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)
#define EXAMINE_SYSCALL	\
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr))
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define EXAMINE_ARG(n)							\
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args) + n * sizeof(__u64))
#define EXAMINE_ARGHI(n)							\
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args) + n * sizeof(__u64) + sizeof(__u32))
#else
#define EXAMINE_ARG(n)							\
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args) + n * sizeof(__u64) + sizeof(_u32))
#define EXAMINE_ARGHI(n)							\
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args) + n * sizeof(__u64)))
#endif
#define ALLOW	\
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
#define ALLOW_SYSCALL(name)	\
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1),	\
	ALLOW
#define FAIL_ECAPMODE	\
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | (ECAPMODE & 0xFFFF))
#define FAIL_SYSCALL(name)	\
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1),	\
	FAIL_ECAPMODE
#ifdef SECCOMP_DATA_TID_PRESENT
/* Build environment includes .tgid and .tid fields in seccomp_data */
#define EXAMINE_TGID	\
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, tgid))
#define EXAMINE_TID	\
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, tid))
#endif

static struct sock_filter capmode_filter[] = {
	VALIDATE_ARCHITECTURE,
	EXAMINE_SYSCALL,

	/* Allowed syscalls */
	ALLOW_SYSCALL(accept),
	ALLOW_SYSCALL(accept4),
	ALLOW_SYSCALL(brk),
#ifdef __NR_cap_rights_get
	ALLOW_SYSCALL(cap_rights_get),
#endif
#ifdef __NR_cap_rights_limit
	ALLOW_SYSCALL(cap_rights_limit),
#endif
	ALLOW_SYSCALL(clock_getres),
	ALLOW_SYSCALL(clock_gettime),
	ALLOW_SYSCALL(clone),
	ALLOW_SYSCALL(close),
	ALLOW_SYSCALL(dup),
	ALLOW_SYSCALL(dup2),
	ALLOW_SYSCALL(dup3),
#ifdef __NR_execveat
	ALLOW_SYSCALL(execveat),
#endif
	ALLOW_SYSCALL(exit),
	ALLOW_SYSCALL(exit_group),
	ALLOW_SYSCALL(faccessat),
	ALLOW_SYSCALL(fchmod),
	ALLOW_SYSCALL(fchmodat),
	ALLOW_SYSCALL(fchown),
	ALLOW_SYSCALL(fchownat),
	ALLOW_SYSCALL(fcntl),
	ALLOW_SYSCALL(fdatasync),
	ALLOW_SYSCALL(fgetxattr),
	ALLOW_SYSCALL(finit_module),
	ALLOW_SYSCALL(flistxattr),
	ALLOW_SYSCALL(flock),
	ALLOW_SYSCALL(fork),
	ALLOW_SYSCALL(fremovexattr),
	ALLOW_SYSCALL(fsetxattr),
	ALLOW_SYSCALL(fstat),
	ALLOW_SYSCALL(fstatfs),
	ALLOW_SYSCALL(fsync),
	ALLOW_SYSCALL(ftruncate),
	ALLOW_SYSCALL(futimesat),
	ALLOW_SYSCALL(getdents),
	ALLOW_SYSCALL(getegid),
	ALLOW_SYSCALL(geteuid),
	ALLOW_SYSCALL(getgid),
	ALLOW_SYSCALL(getgroups),
	ALLOW_SYSCALL(getitimer),
	ALLOW_SYSCALL(getpeername),
	ALLOW_SYSCALL(getpgid),
	ALLOW_SYSCALL(getpgrp),
	ALLOW_SYSCALL(getpid),
	ALLOW_SYSCALL(getppid),
	ALLOW_SYSCALL(getpriority),
	ALLOW_SYSCALL(getresgid),
	ALLOW_SYSCALL(getresuid),
	ALLOW_SYSCALL(getrlimit),
	ALLOW_SYSCALL(getrusage),
	ALLOW_SYSCALL(getsid),
	ALLOW_SYSCALL(getsockname),
	ALLOW_SYSCALL(getsockopt),
	ALLOW_SYSCALL(gettid),
	ALLOW_SYSCALL(gettimeofday),
	ALLOW_SYSCALL(getuid),
	ALLOW_SYSCALL(ioctl),
	ALLOW_SYSCALL(linkat),
	ALLOW_SYSCALL(listen),
	ALLOW_SYSCALL(lseek),
	ALLOW_SYSCALL(madvise),
	ALLOW_SYSCALL(mincore),
	ALLOW_SYSCALL(mkdirat),
	ALLOW_SYSCALL(mknodat),
	ALLOW_SYSCALL(mlock),
	ALLOW_SYSCALL(mlockall),
	ALLOW_SYSCALL(mprotect),
	ALLOW_SYSCALL(mq_getsetattr),
	ALLOW_SYSCALL(mq_notify),
	ALLOW_SYSCALL(mq_timedreceive),
	ALLOW_SYSCALL(mq_timedsend),
	ALLOW_SYSCALL(msync),
	ALLOW_SYSCALL(munlock),
	ALLOW_SYSCALL(munlockall),
	ALLOW_SYSCALL(munmap),
	ALLOW_SYSCALL(nanosleep),
	ALLOW_SYSCALL(newfstatat),
#ifdef __NR_pdfork
	ALLOW_SYSCALL(pdfork),
#endif
#ifdef __NR_pdgetpid
	ALLOW_SYSCALL(pdgetpid),
#endif
#ifdef __NR_pdkill
	ALLOW_SYSCALL(pdkill),
#endif
#ifdef __NR_pdwait4
	ALLOW_SYSCALL(pdwait4),
#endif
	ALLOW_SYSCALL(pipe),
	ALLOW_SYSCALL(pipe2),
	ALLOW_SYSCALL(poll),
	ALLOW_SYSCALL(ppoll),
	ALLOW_SYSCALL(pread64),
	ALLOW_SYSCALL(preadv),
	ALLOW_SYSCALL(pselect6),
	ALLOW_SYSCALL(pwrite64),
	ALLOW_SYSCALL(pwritev),
	ALLOW_SYSCALL(read),
	ALLOW_SYSCALL(readahead),
	ALLOW_SYSCALL(readlinkat),
	ALLOW_SYSCALL(readv),
	ALLOW_SYSCALL(recvfrom),
	ALLOW_SYSCALL(recvmmsg),
	ALLOW_SYSCALL(recvmsg),
	ALLOW_SYSCALL(renameat),
	ALLOW_SYSCALL(rt_sigaction),
	ALLOW_SYSCALL(rt_sigpending),
	ALLOW_SYSCALL(rt_sigprocmask),
	ALLOW_SYSCALL(rt_sigqueueinfo),
	ALLOW_SYSCALL(rt_sigreturn),
	ALLOW_SYSCALL(rt_sigsuspend),
	ALLOW_SYSCALL(rt_sigtimedwait),
	ALLOW_SYSCALL(rt_tgsigqueueinfo),
	ALLOW_SYSCALL(sched_get_priority_max),
	ALLOW_SYSCALL(sched_get_priority_min),
	ALLOW_SYSCALL(sched_getparam),
	ALLOW_SYSCALL(sched_getscheduler),
	ALLOW_SYSCALL(sched_rr_get_interval),
	ALLOW_SYSCALL(sched_setparam),
	ALLOW_SYSCALL(sched_setscheduler),
	ALLOW_SYSCALL(sched_yield),
	ALLOW_SYSCALL(select),
	ALLOW_SYSCALL(sendfile),
	ALLOW_SYSCALL(sendmmsg),
	ALLOW_SYSCALL(sendmsg),
	ALLOW_SYSCALL(sendto),
	ALLOW_SYSCALL(setfsgid),
	ALLOW_SYSCALL(setfsuid),
	ALLOW_SYSCALL(setgid),
	ALLOW_SYSCALL(setitimer),
	ALLOW_SYSCALL(setpriority),
	ALLOW_SYSCALL(setregid),
	ALLOW_SYSCALL(setresgid),
	ALLOW_SYSCALL(setresuid),
	ALLOW_SYSCALL(setreuid),
	ALLOW_SYSCALL(setrlimit),
	ALLOW_SYSCALL(setsid),
	ALLOW_SYSCALL(setsockopt),
	ALLOW_SYSCALL(setuid),
	ALLOW_SYSCALL(shutdown),
	ALLOW_SYSCALL(sigaltstack),
	ALLOW_SYSCALL(socket),
	ALLOW_SYSCALL(socketpair),
	ALLOW_SYSCALL(symlinkat),
	ALLOW_SYSCALL(sync),
	ALLOW_SYSCALL(syncfs),
	ALLOW_SYSCALL(sync_file_range),
	ALLOW_SYSCALL(umask),
	ALLOW_SYSCALL(uname),
	ALLOW_SYSCALL(unlinkat),
	ALLOW_SYSCALL(unshare),
	ALLOW_SYSCALL(utimensat),
	ALLOW_SYSCALL(vfork),
	ALLOW_SYSCALL(vmsplice),
	ALLOW_SYSCALL(write),
	ALLOW_SYSCALL(writev),

	/* Special syscalls */

	/* arch_prctl(2) */
#if defined(__NR_arch_prctl)
	/* TODO(drysdale): sort out other architectures */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_arch_prctl, 0, 11),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	EXAMINE_ARG(0),  /* code */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_GET_FS, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_GET_GS, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_SET_FS, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_SET_GS, 0, 1),
	ALLOW,
	FAIL_ECAPMODE,
#endif

#ifdef SECCOMP_DATA_TID_PRESENT
	/* tgkill(2)/kill(2): check arg[0] vs current tgid. */
	/* First check info is available */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_tgkill, 1, 0),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_kill, 0, 10),
	BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),  /* A <- data len */
	BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K,
		offsetof(struct seccomp_data, tgid) + sizeof(pid_t),
		0, 1),
	BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K,
		offsetof(struct seccomp_data, tid) + sizeof(pid_t),
		1, 0),
	FAIL_ECAPMODE,
	EXAMINE_ARG(0),  /* A <- specified pid */
	BPF_STMT(BPF_MISC+BPF_TAX, 0),  /* X <- A */
	EXAMINE_TGID,  /* A <- actual tgid */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_X, 0, 0, 1),
	ALLOW,
	FAIL_ECAPMODE,
#else
	/* kill(2): want to check for current tid, but can't. */
#endif

	/* mmap(2) */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_mmap, 0, 6),
	EXAMINE_ARG(3),  /* flags */
	BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, MAP_ANONYMOUS, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, ~(MAP_SHARED|MAP_PRIVATE|MAP_32BIT|MAP_FIXED|MAP_HUGETLB|MAP_NONBLOCK|MAP_NORESERVE|MAP_POPULATE|MAP_STACK), 0, 1),
	FAIL_ECAPMODE,
	ALLOW,

	/* openat(2) */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_openat, 0, 7),
	EXAMINE_ARG(0),  /* dfd */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AT_FDCWD, 0, 1),
	FAIL_ECAPMODE,
	EXAMINE_ARG(2),  /* flags */
	BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, ~(O_WRONLY|O_RDWR|O_CREAT|O_EXCL|O_TRUNC|O_APPEND|FASYNC|O_CLOEXEC|O_DIRECT|O_DIRECTORY|O_LARGEFILE| O_NOATIME|O_NOCTTY|O_NOFOLLOW|O_NONBLOCK|O_SYNC), 0, 1),
	FAIL_ECAPMODE,
	ALLOW,

	/* prctl(2) */
#ifdef PR_GET_OPENAT_BENEATH
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_prctl, 0, 36),
#else
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_prctl, 0, 34),
#endif
	EXAMINE_ARG(0),  /* option */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, PR_CAPBSET_READ, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, PR_CAPBSET_DROP, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, PR_GET_DUMPABLE, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, PR_GET_ENDIAN, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, PR_GET_FPEMU, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, PR_GET_KEEPCAPS, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, PR_GET_NAME, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, PR_GET_NO_NEW_PRIVS, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, PR_GET_PDEATHSIG, 0, 1),
	ALLOW,
#ifdef PR_GET_OPENAT_BENEATH
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, PR_GET_OPENAT_BENEATH, 0, 1),
	ALLOW,
#endif
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, PR_GET_SECCOMP, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, PR_GET_SECUREBITS, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, PR_GET_TIMERSLACK, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, PR_GET_TIMING, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, PR_GET_TSC, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, PR_GET_UNALIGN, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, PR_MCE_KILL_GET, 0, 1),
	ALLOW,
	FAIL_ECAPMODE,

	/* Fail everything else */
	FAIL_ECAPMODE,
};
static struct sock_fprog capmode_fprog = {
	.len = (sizeof(capmode_filter) / sizeof(capmode_filter[0])),
	.filter = capmode_filter
};

static void print_filter(struct sock_fprog *bpf) {
	int pc;
	for (pc = 1; pc <= bpf->len; pc++) {
		struct sock_filter *filter = &(bpf->filter[pc-1]);
		printf(" [%d] = code=%04x, jt=%u, jf=%u, k=%d\n",
			pc, filter->code, filter->jt, filter->jf, filter->k);
	}
}

int seccomp_(unsigned int op, unsigned int flags, struct sock_fprog *filter) {
	errno = 0;
	return syscall(__NR_seccomp, op, flags, filter);
}

int cap_enter() {
	int rc = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (rc < 0) return rc;
#ifdef PR_SET_OPENAT_BENEATH
	rc = prctl(PR_SET_OPENAT_BENEATH, 1 , PR_SET_OPENAT_BENEATH_TSYNC, 0, 0);
	if (rc < 0) return rc;
#endif
	return seccomp_(SECCOMP_SET_MODE_FILTER,
			SECCOMP_FILTER_FLAG_TSYNC,
			&capmode_fprog);
}

int cap_getmode(unsigned int *mode) {
	int beneath = 1;
	int seccomp = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
	if (seccomp < 0) return seccomp;
#ifdef PR_GET_OPENAT_BENEATH
	beneath = prctl(PR_GET_OPENAT_BENEATH, 0, 0, 0, 0);
	if (beneath < 0) return beneath;
#endif
	*mode = (seccomp == SECCOMP_MODE_FILTER && beneath == 1);
	return 0;
}

#endif /* __linux__ */
