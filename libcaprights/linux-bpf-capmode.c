/* seccomp-BPF implementation of capability mode */
#ifdef __linux__
#define _GNU_SOURCE  /* to get O_* constants */
#include "config.h"
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <syscall.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/fcntl.h>
#include <linux/net.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <linux/wait.h>
#include <asm/prctl.h>

#include <seccomp.h>  /* requires libseccomp, Debian package libseccomp-dev */


#ifndef VALID_MAP_FLAGS
#define VALID_MAP_FLAGS (MAP_SHARED|MAP_PRIVATE|MAP_32BIT|MAP_FIXED|MAP_HUGETLB|MAP_NONBLOCK|MAP_NORESERVE|MAP_POPULATE|MAP_STACK)
#endif

#ifndef VALID_OPENAT_FLAGS
#ifdef O_BENEATH
#define VALID_OPENAT_FLAGS (O_WRONLY|O_RDWR|O_CREAT|O_EXCL|O_TRUNC|O_APPEND|FASYNC|O_CLOEXEC|O_DIRECT|O_DIRECTORY|O_LARGEFILE|O_NOATIME|O_NOCTTY|O_NOFOLLOW|O_NONBLOCK|O_SYNC|O_BENEATH)
#else
#define VALID_OPENAT_FLAGS (O_WRONLY|O_RDWR|O_CREAT|O_EXCL|O_TRUNC|O_APPEND|FASYNC|O_CLOEXEC|O_DIRECT|O_DIRECTORY|O_LARGEFILE|O_NOATIME|O_NOCTTY|O_NOFOLLOW|O_NONBLOCK|O_SYNC)
#endif
#endif

#define ALLOW_SYSCALL(name) \
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(name), 0); \
	if (rc != 0) return -1;

static int add_seccomp(void) {
	scmp_filter_ctx ctx = NULL;
	int rc;

	ctx = seccomp_init(SCMP_ACT_ERRNO(ECAPMODE));
	if (ctx == NULL)
		return -1;

	/* Allowed syscalls: start with most common calls */
	ALLOW_SYSCALL(futex);
	ALLOW_SYSCALL(poll);
	ALLOW_SYSCALL(read);
	ALLOW_SYSCALL(write);
	ALLOW_SYSCALL(readv);
	ALLOW_SYSCALL(writev);
	ALLOW_SYSCALL(close);
	ALLOW_SYSCALL(recvmsg);
	ALLOW_SYSCALL(recvfrom);
	ALLOW_SYSCALL(madvise);
	ALLOW_SYSCALL(gettid);
	ALLOW_SYSCALL(fstat);
	ALLOW_SYSCALL(fstat64);
	ALLOW_SYSCALL(fstatat64);
	ALLOW_SYSCALL(fcntl);
	ALLOW_SYSCALL(fcntl64);
	ALLOW_SYSCALL(sendto);
#ifdef OMIT
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYSCALL_NUM(mmap), 0, 9),
	EXAMINE_ARGHI(3),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 1, 0),
	FAIL_ECAPMODE,
	EXAMINE_ARG(3),  /* flags */
	BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, MAP_ANONYMOUS, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, ~(VALID_MAP_FLAGS), 0, 1),
	FAIL_ECAPMODE,
	ALLOW,

	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYSCALL_NUM(mmap2), 0, 9),
	EXAMINE_ARGHI(3),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 1, 0),
	FAIL_ECAPMODE,
	EXAMINE_ARG(3),  /* flags */
	BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, MAP_ANONYMOUS, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, ~(VALID_MAP_FLAGS), 0, 1),
	FAIL_ECAPMODE,
	ALLOW,

	/* openat(2) */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYSCALL_NUM(openat), 0, 13),
	EXAMINE_ARGHI(0),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 1, 0),
	FAIL_ECAPMODE,
	EXAMINE_ARG(0),  /* dfd */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AT_FDCWD, 0, 1),
	FAIL_ECAPMODE,
	EXAMINE_ARGHI(2),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 1, 0),
	FAIL_ECAPMODE,
	EXAMINE_ARG(2),  /* flags */
	BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, ~(VALID_OPENAT_FLAGS), 0, 1),
	FAIL_ECAPMODE,
	ALLOW,
#endif
	ALLOW_SYSCALL(lseek);

	/* Allowed syscalls: alphabetic list of remainder */
	ALLOW_SYSCALL(accept);
	ALLOW_SYSCALL(accept4);
	ALLOW_SYSCALL(brk);
	ALLOW_SYSCALL(cap_rights_get);
	ALLOW_SYSCALL(cap_rights_limit);
	ALLOW_SYSCALL(clock_getres);
	ALLOW_SYSCALL(clock_gettime);
	ALLOW_SYSCALL(clone);
	ALLOW_SYSCALL(clone4);
	ALLOW_SYSCALL(dup);
	ALLOW_SYSCALL(dup2);
	ALLOW_SYSCALL(dup3);
	ALLOW_SYSCALL(execveat);
	ALLOW_SYSCALL(exit);
	ALLOW_SYSCALL(exit_group);
	ALLOW_SYSCALL(faccessat);
	ALLOW_SYSCALL(fchmod);
	ALLOW_SYSCALL(fchmodat);
	ALLOW_SYSCALL(fchown);
	ALLOW_SYSCALL(fchown32);
	ALLOW_SYSCALL(fchownat);
	ALLOW_SYSCALL(fdatasync);
	ALLOW_SYSCALL(fgetxattr);
	ALLOW_SYSCALL(finit_module);
	ALLOW_SYSCALL(flistxattr);
	ALLOW_SYSCALL(flock);
	ALLOW_SYSCALL(fork);
	ALLOW_SYSCALL(fremovexattr);
	ALLOW_SYSCALL(fsetxattr);
	ALLOW_SYSCALL(fstatfs);
	ALLOW_SYSCALL(fsync);
	ALLOW_SYSCALL(ftruncate);
	ALLOW_SYSCALL(ftruncate64);
	ALLOW_SYSCALL(futimesat);
	ALLOW_SYSCALL(get_robust_list);
	ALLOW_SYSCALL(getdents);
	ALLOW_SYSCALL(getdents64);
	ALLOW_SYSCALL(getegid);
	ALLOW_SYSCALL(geteuid);
	ALLOW_SYSCALL(getgid);
	ALLOW_SYSCALL(getgroups);
	ALLOW_SYSCALL(getitimer);
	ALLOW_SYSCALL(getpeername);
	ALLOW_SYSCALL(getpgid);
	ALLOW_SYSCALL(getpgrp);
	ALLOW_SYSCALL(getpid);
	ALLOW_SYSCALL(getppid);
	ALLOW_SYSCALL(getpriority);
	ALLOW_SYSCALL(getrandom);
	ALLOW_SYSCALL(getresgid);
	ALLOW_SYSCALL(getresgid32);
	ALLOW_SYSCALL(getresuid);
	ALLOW_SYSCALL(getresuid32);
	ALLOW_SYSCALL(getrlimit);
	ALLOW_SYSCALL(getrusage);
	ALLOW_SYSCALL(getsid);
	ALLOW_SYSCALL(getsockname);
	ALLOW_SYSCALL(getsockopt);
	ALLOW_SYSCALL(gettimeofday);
	ALLOW_SYSCALL(getuid);
	ALLOW_SYSCALL(ioctl);
	ALLOW_SYSCALL(linkat);
	ALLOW_SYSCALL(listen);
	ALLOW_SYSCALL(memfd_create);
	ALLOW_SYSCALL(mincore);
	ALLOW_SYSCALL(mkdirat);
	ALLOW_SYSCALL(mknodat);
	ALLOW_SYSCALL(mlock);
	ALLOW_SYSCALL(mlockall);
	ALLOW_SYSCALL(mprotect);
	ALLOW_SYSCALL(mq_getsetattr);
	ALLOW_SYSCALL(mq_notify);
	ALLOW_SYSCALL(mq_timedreceive);
	ALLOW_SYSCALL(mq_timedsend);
	ALLOW_SYSCALL(msync);
	ALLOW_SYSCALL(munlock);
	ALLOW_SYSCALL(munlockall);
	ALLOW_SYSCALL(munmap);
	ALLOW_SYSCALL(nanosleep);
	ALLOW_SYSCALL(newfstatat);
	ALLOW_SYSCALL(_newselect);
	ALLOW_SYSCALL(oldfstat);
	ALLOW_SYSCALL(pipe);
	ALLOW_SYSCALL(pipe2);
	ALLOW_SYSCALL(ppoll);
	ALLOW_SYSCALL(pread64);
	ALLOW_SYSCALL(preadv);
	ALLOW_SYSCALL(pselect6);
	ALLOW_SYSCALL(pwrite64);
	ALLOW_SYSCALL(pwritev);
	ALLOW_SYSCALL(readahead);
	ALLOW_SYSCALL(readlinkat);
	ALLOW_SYSCALL(recvmmsg);
	ALLOW_SYSCALL(renameat);
	ALLOW_SYSCALL(restart_syscall);
	ALLOW_SYSCALL(rt_sigaction);
	ALLOW_SYSCALL(rt_sigpending);
	ALLOW_SYSCALL(rt_sigprocmask);
	ALLOW_SYSCALL(rt_sigqueueinfo);
	ALLOW_SYSCALL(rt_sigreturn);
	ALLOW_SYSCALL(rt_sigsuspend);
	ALLOW_SYSCALL(rt_sigtimedwait);
	ALLOW_SYSCALL(rt_tgsigqueueinfo);
	ALLOW_SYSCALL(sched_get_priority_max);
	ALLOW_SYSCALL(sched_get_priority_min);
	ALLOW_SYSCALL(sched_getparam);
	ALLOW_SYSCALL(sched_getscheduler);
	ALLOW_SYSCALL(sched_rr_get_interval);
	ALLOW_SYSCALL(sched_setparam);
	ALLOW_SYSCALL(sched_setscheduler);
	ALLOW_SYSCALL(sched_yield);
	ALLOW_SYSCALL(seccomp);
	ALLOW_SYSCALL(select);
	ALLOW_SYSCALL(sendfile);
	ALLOW_SYSCALL(sendfile64);
	ALLOW_SYSCALL(sendmmsg);
	ALLOW_SYSCALL(sendmsg);
	ALLOW_SYSCALL(set_robust_list);
	ALLOW_SYSCALL(setfsgid);
	ALLOW_SYSCALL(setfsgid32);
	ALLOW_SYSCALL(setfsuid);
	ALLOW_SYSCALL(setfsuid32);
	ALLOW_SYSCALL(setgid);
	ALLOW_SYSCALL(setgid32);
	ALLOW_SYSCALL(setitimer);
	ALLOW_SYSCALL(setpriority);
	ALLOW_SYSCALL(setregid);
	ALLOW_SYSCALL(setregid32);
	ALLOW_SYSCALL(setresgid);
	ALLOW_SYSCALL(setresgid32);
	ALLOW_SYSCALL(setresuid);
	ALLOW_SYSCALL(setresuid32);
	ALLOW_SYSCALL(setreuid);
	ALLOW_SYSCALL(setreuid32);
	ALLOW_SYSCALL(setrlimit);
	ALLOW_SYSCALL(setsid);
	ALLOW_SYSCALL(setsockopt);
	ALLOW_SYSCALL(setuid);
	ALLOW_SYSCALL(setuid32);
	ALLOW_SYSCALL(set_thread_area);
	ALLOW_SYSCALL(shutdown);
	ALLOW_SYSCALL(sigaltstack);
	ALLOW_SYSCALL(sigaction);
	ALLOW_SYSCALL(signal);
	ALLOW_SYSCALL(signalfd);
	ALLOW_SYSCALL(signalfd4);
	ALLOW_SYSCALL(sigpending);
	ALLOW_SYSCALL(sigprocmask);
	ALLOW_SYSCALL(sigreturn);
	ALLOW_SYSCALL(sigsuspend);
	ALLOW_SYSCALL(socket);
	ALLOW_SYSCALL(socketpair);
	ALLOW_SYSCALL(symlinkat);
	ALLOW_SYSCALL(sync);
	ALLOW_SYSCALL(syncfs);
	ALLOW_SYSCALL(sync_file_range);
	ALLOW_SYSCALL(umask);
	ALLOW_SYSCALL(uname);
	ALLOW_SYSCALL(unlinkat);
	ALLOW_SYSCALL(unshare);
	ALLOW_SYSCALL(utimensat);
	ALLOW_SYSCALL(vfork);
	ALLOW_SYSCALL(vmsplice);

	/* Special syscalls */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 4,
			      SCMP_A0(SCMP_CMP_EQ, ARCH_GET_FS),
			      SCMP_A0(SCMP_CMP_EQ, ARCH_GET_GS),
			      SCMP_A0(SCMP_CMP_EQ, ARCH_SET_FS),
			      SCMP_A0(SCMP_CMP_EQ, ARCH_SET_GS));
	if (rc != 0) return -1;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl),
#ifdef PR_GET_OPENAT_BENEATH
			      1 +
#endif
			      16,
#ifdef PR_GET_OPENAT_BENEATH
			      SCMP_A0(SCMP_CMP_EQ, PR_GET_OPENAT_BENEATH),
#endif
			      SCMP_A0(SCMP_CMP_EQ, PR_CAPBSET_READ),
			      SCMP_A0(SCMP_CMP_EQ, PR_CAPBSET_DROP),
			      SCMP_A0(SCMP_CMP_EQ, PR_GET_DUMPABLE),
			      SCMP_A0(SCMP_CMP_EQ, PR_GET_ENDIAN),
			      SCMP_A0(SCMP_CMP_EQ, PR_GET_FPEMU),
			      SCMP_A0(SCMP_CMP_EQ, PR_GET_KEEPCAPS),
			      SCMP_A0(SCMP_CMP_EQ, PR_GET_NAME),
			      SCMP_A0(SCMP_CMP_EQ, PR_GET_NO_NEW_PRIVS),
			      SCMP_A0(SCMP_CMP_EQ, PR_GET_PDEATHSIG),
			      SCMP_A0(SCMP_CMP_EQ, PR_GET_SECCOMP),
			      SCMP_A0(SCMP_CMP_EQ, PR_GET_SECUREBITS),
			      SCMP_A0(SCMP_CMP_EQ, PR_GET_TIMERSLACK),
			      SCMP_A0(SCMP_CMP_EQ, PR_GET_TIMING),
			      SCMP_A0(SCMP_CMP_EQ, PR_GET_TSC),
			      SCMP_A0(SCMP_CMP_EQ, PR_GET_UNALIGN),
			      SCMP_A0(SCMP_CMP_EQ, PR_MCE_KILL_GET));
	if (rc != 0) return -1;

#ifdef WCLONEFD
	/* wait4(2) */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 1,
			      SCMP_A2(SCMP_CMP_MASKED_EQ, WCLONEFD, WCLONEFD));
	if (rc != 0) return -1;
#endif

#ifdef OMIT_AND_SECCOMP_DATA_TID_PRESENT
	/* tgkill(2)/kill(2): check arg[0] vs current tgid. */
	/* First check info is available */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYSCALL_NUM(tgkill), 1, 0),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYSCALL_NUM(kill), 0, 13),
	BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),  /* A <- data len */
	BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K,
		offsetof(struct seccomp_data, tgid) + sizeof(pid_t),
		0, 1),
	BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K,
		offsetof(struct seccomp_data, tid) + sizeof(pid_t),
		1, 0),
	FAIL_ECAPMODE,
	EXAMINE_ARGHI(0),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 1, 0),
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

	return 0;
}

int cap_enter() {
	int rc = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (rc < 0) return rc;
#ifdef PR_SET_OPENAT_BENEATH
	rc = prctl(PR_SET_OPENAT_BENEATH, 1 , PR_SET_OPENAT_BENEATH_TSYNC, 0, 0);
	if (rc < 0) return rc;
#endif
	return add_seccomp();
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

bool cap_sandboxed(void) {
	unsigned int mode;
	if (cap_getmode(&mode) != 0) return false;
	return (mode == 1);
}

#endif /* __linux__ */
