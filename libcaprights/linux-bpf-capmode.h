/*
 * No include guards: this file is potentially included multiple times with
 * different definitions of:
 *   - SYSCALL_NUM(name) : map syscall name to constant
 *   - SYSCALL_PREFIX : 0=none, 1=amd64, 2=ia32
 *   - SYSCALL_ARCH : architecture value this filter is approprate for
 *   - SYSCALL_FILTER : name of the filter variable.
 *
 * For any system call where there's a chance that it might not be present
 * (either because it's specific to one sub-arch, or because it's a recent
 * addition), we therefore need to surround the BPF fragment with an #ifdef
 * that identifies whether the relevant constant is available.
 */

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

static struct sock_filter SYSCALL_FILTER[] = {
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)), /* load arch */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYSCALL_ARCH, 1, 0),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),

	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)), /* load syscall# */
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, SYSCALL_NUM_MASK), /* mask off x32 bit if present */

	/* Allowed syscalls */
#if ((SYSCALL_PREFIX == 0 && defined(__NR_accept)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_accept)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_accept)))
	ALLOW_SYSCALL(accept),
#endif
#if ((SYSCALL_PREFIX == 0 && defined(__NR_accept4)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_accept4)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_accept4)))
	ALLOW_SYSCALL(accept4),
#endif
	ALLOW_SYSCALL(brk),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_cap_rights_get)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_cap_rights_get)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_cap_rights_get)))
	ALLOW_SYSCALL(cap_rights_get),
#endif
#if ((SYSCALL_PREFIX == 0 && defined(__NR_cap_rights_limit)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_cap_rights_limit)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_cap_rights_limit)))
	ALLOW_SYSCALL(cap_rights_limit),
#endif
	ALLOW_SYSCALL(clock_getres),
	ALLOW_SYSCALL(clock_gettime),
	ALLOW_SYSCALL(clone),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_clone4)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_clone4)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_clone4)))
	ALLOW_SYSCALL(clone4),
#endif
	ALLOW_SYSCALL(close),
	ALLOW_SYSCALL(dup),
	ALLOW_SYSCALL(dup2),
	ALLOW_SYSCALL(dup3),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_execveat)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_execveat)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_execveat)))
	ALLOW_SYSCALL(execveat),
#endif
	ALLOW_SYSCALL(exit),
	ALLOW_SYSCALL(exit_group),
	ALLOW_SYSCALL(faccessat),
	ALLOW_SYSCALL(fchmod),
	ALLOW_SYSCALL(fchmodat),
	ALLOW_SYSCALL(fchown),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_fchown32)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_fchown32)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_fchown32)))
	ALLOW_SYSCALL(fchown32),
#endif
	ALLOW_SYSCALL(fchownat),
	ALLOW_SYSCALL(fcntl),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_fcntl64)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_fcntl64)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_fcntl64)))
	ALLOW_SYSCALL(fcntl64),
#endif
	ALLOW_SYSCALL(fdatasync),
	ALLOW_SYSCALL(fgetxattr),
	ALLOW_SYSCALL(finit_module),
	ALLOW_SYSCALL(flistxattr),
	ALLOW_SYSCALL(flock),
	ALLOW_SYSCALL(fork),
	ALLOW_SYSCALL(fremovexattr),
	ALLOW_SYSCALL(fsetxattr),
	ALLOW_SYSCALL(fstat),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_fstat64)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_fstat64)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_fstat64)))
	ALLOW_SYSCALL(fstat64),
#endif
#if ((SYSCALL_PREFIX == 0 && defined(__NR_fstatat64)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_fstatat64)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_fstatat64)))
	ALLOW_SYSCALL(fstatat64),
#endif
	ALLOW_SYSCALL(fstatfs),
	ALLOW_SYSCALL(fsync),
	ALLOW_SYSCALL(ftruncate),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_ftruncate64)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_ftruncate64)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_ftruncate64)))
	ALLOW_SYSCALL(ftruncate64),
#endif
	ALLOW_SYSCALL(futex),
	ALLOW_SYSCALL(futimesat),
	ALLOW_SYSCALL(get_robust_list),
	ALLOW_SYSCALL(getdents),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_getdents64)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_getdents64)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_getdents64)))
	ALLOW_SYSCALL(getdents64),
#endif
	ALLOW_SYSCALL(getegid),
	ALLOW_SYSCALL(geteuid),
	ALLOW_SYSCALL(getgid),
	ALLOW_SYSCALL(getgroups),
	ALLOW_SYSCALL(getitimer),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_getpeername)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_getpeername)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_getpeername)))
	ALLOW_SYSCALL(getpeername),
#endif
	ALLOW_SYSCALL(getpgid),
	ALLOW_SYSCALL(getpgrp),
	ALLOW_SYSCALL(getpid),
	ALLOW_SYSCALL(getppid),
	ALLOW_SYSCALL(getpriority),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_getrandom)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_getrandom)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_getrandom)))
	ALLOW_SYSCALL(getrandom),
#endif
	ALLOW_SYSCALL(getresgid),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_getresgid32)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_getresgid32)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_getresgid32)))
	ALLOW_SYSCALL(getresgid32),
#endif
	ALLOW_SYSCALL(getresuid),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_getresuid32)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_getresuid32)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_getresuid32)))
	ALLOW_SYSCALL(getresuid32),
#endif
	ALLOW_SYSCALL(getrlimit),
	ALLOW_SYSCALL(getrusage),
	ALLOW_SYSCALL(getsid),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_getsockname)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_getsockname)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_getsockname)))
	ALLOW_SYSCALL(getsockname),
#endif
#if ((SYSCALL_PREFIX == 0 && defined(__NR_getsockopt)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_getsockopt)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_getsockopt)))
	ALLOW_SYSCALL(getsockopt),
#endif
	ALLOW_SYSCALL(gettid),
	ALLOW_SYSCALL(gettimeofday),
	ALLOW_SYSCALL(getuid),
	ALLOW_SYSCALL(ioctl),
	ALLOW_SYSCALL(linkat),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_listen)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_listen)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_listen)))
	ALLOW_SYSCALL(listen),
#endif
	ALLOW_SYSCALL(lseek),
	ALLOW_SYSCALL(madvise),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_memfd_create)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_memfd_create)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_memfd_create)))
	ALLOW_SYSCALL(memfd_create),
#endif
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
#if ((SYSCALL_PREFIX == 0 && defined(__NR_newfstatat)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_newfstatat)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_newfstatat)))
	ALLOW_SYSCALL(newfstatat),
#endif
#if ((SYSCALL_PREFIX == 0 && defined(__NR__newselect)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64__newselect)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32__newselect)))
	ALLOW_SYSCALL(_newselect),
#endif
#if ((SYSCALL_PREFIX == 0 && defined(__NR_oldfstat)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_oldfstat)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_oldfstat)))
	ALLOW_SYSCALL(oldfstat),
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
#if ((SYSCALL_PREFIX == 0 && defined(__NR_recvfrom)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_recvfrom)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_recvfrom)))
	ALLOW_SYSCALL(recvfrom),
#endif
	ALLOW_SYSCALL(recvmmsg),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_recvmsg)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_recvmsg)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_recvmsg)))
	ALLOW_SYSCALL(recvmsg),
#endif
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
#if ((SYSCALL_PREFIX == 0 && defined(__NR_seccomp)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_seccomp)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_seccomp)))
	ALLOW_SYSCALL(seccomp),
#endif
	ALLOW_SYSCALL(select),
	ALLOW_SYSCALL(sendfile),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_sendfile64)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_sendfile64)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_sendfile64)))
	ALLOW_SYSCALL(sendfile64),
#endif
	ALLOW_SYSCALL(sendmmsg),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_sendmsg)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_sendmsg)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_sendmsg)))
	ALLOW_SYSCALL(sendmsg),
#endif
#if ((SYSCALL_PREFIX == 0 && defined(__NR_sendto)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_sendto)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_sendto)))
	ALLOW_SYSCALL(sendto),
#endif

	ALLOW_SYSCALL(set_robust_list),
	ALLOW_SYSCALL(setfsgid),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_setfsgid32)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_setfsgid32)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_setfsgid32)))
	ALLOW_SYSCALL(setfsgid32),
#endif
	ALLOW_SYSCALL(setfsuid),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_setfsuid32)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_setfsuid32)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_setfsuid32)))
	ALLOW_SYSCALL(setfsuid32),
#endif
	ALLOW_SYSCALL(setgid),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_setgid32)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_setgid32)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_setgid32)))
	ALLOW_SYSCALL(setgid32),
#endif
	ALLOW_SYSCALL(setitimer),
	ALLOW_SYSCALL(setpriority),
	ALLOW_SYSCALL(setregid),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_setregid32)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_setregid32)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_setregid32)))
	ALLOW_SYSCALL(setregid32),
#endif
	ALLOW_SYSCALL(setresgid),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_setresgid32)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_setresgid32)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_setresgid32)))
	ALLOW_SYSCALL(setresgid32),
#endif
	ALLOW_SYSCALL(setresuid),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_setresuid32)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_setresuid32)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_setresuid32)))
	ALLOW_SYSCALL(setresuid32),
#endif
	ALLOW_SYSCALL(setreuid),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_setreuid32)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_setreuid32)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_setreuid32)))
	ALLOW_SYSCALL(setreuid32),
#endif
	ALLOW_SYSCALL(setrlimit),
	ALLOW_SYSCALL(setsid),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_setsockopt)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_setsockopt)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_setsockopt)))
	ALLOW_SYSCALL(setsockopt),
#endif
	ALLOW_SYSCALL(setuid),
#if ((SYSCALL_PREFIX == 0 && defined(__NR_setuid32)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_setuid32)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_setuid32)))
	ALLOW_SYSCALL(setuid32),
#endif
#if ((SYSCALL_PREFIX == 0 && defined(__NR_set_thread_area)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_set_thread_area)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_set_thread_area)))
	ALLOW_SYSCALL(set_thread_area),
#endif
#if ((SYSCALL_PREFIX == 0 && defined(__NR_shutdown)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_shutdown)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_shutdown)))
	ALLOW_SYSCALL(shutdown),
#endif
	ALLOW_SYSCALL(sigaltstack),

#if ((SYSCALL_PREFIX == 0 && defined(__NR_sigaction)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_sigaction)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_sigaction)))
	ALLOW_SYSCALL(sigaction),
#endif
#if ((SYSCALL_PREFIX == 0 && defined(__NR_signal)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_signal)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_signal)))
	ALLOW_SYSCALL(signal),
#endif
#if ((SYSCALL_PREFIX == 0 && defined(__NR_signalfd)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_signalfd)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_signalfd)))
	ALLOW_SYSCALL(signalfd),
#endif
#if ((SYSCALL_PREFIX == 0 && defined(__NR_signalfd4)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_signalfd4)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_signalfd4)))
	ALLOW_SYSCALL(signalfd4),
#endif
#if ((SYSCALL_PREFIX == 0 && defined(__NR_sigpending)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_sigpending)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_sigpending)))
	ALLOW_SYSCALL(sigpending),
#endif
#if ((SYSCALL_PREFIX == 0 && defined(__NR_sigprocmask)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_sigprocmask)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_sigprocmask)))
	ALLOW_SYSCALL(sigprocmask),
#endif
#if ((SYSCALL_PREFIX == 0 && defined(__NR_sigreturn)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_sigreturn)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_sigreturn)))
	ALLOW_SYSCALL(sigreturn),
#endif
#if ((SYSCALL_PREFIX == 0 && defined(__NR_sigsuspend)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_sigsuspend)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_sigsuspend)))
	ALLOW_SYSCALL(sigsuspend),
#endif

#if ((SYSCALL_PREFIX == 0 && defined(__NR_socket)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_socket)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_socket)))
	ALLOW_SYSCALL(socket),
#endif
#if ((SYSCALL_PREFIX == 0 && defined(__NR_socketcall)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_socketcall)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_socketcall)))
	/* socketcall is a multiplexor equivalent to various other syscalls */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYSCALL_NUM(socketcall), 0, 38),
	EXAMINE_ARG(0),  /* call */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_SOCKET, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_LISTEN, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_ACCEPT, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_GETSOCKNAME, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_GETPEERNAME, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_SOCKETPAIR, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_SEND, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_SENDTO, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_RECV, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_RECVFROM, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_SHUTDOWN, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_SETSOCKOPT, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_GETSOCKOPT, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_SENDMSG, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_SENDMMSG, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_RECVMSG, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_RECVMMSG, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_ACCEPT4, 0, 1),
	ALLOW,
	FAIL_ECAPMODE,  /* Deny SYS_BIND, SYS_CONNECT */
#endif
#if ((SYSCALL_PREFIX == 0 && defined(__NR_socketpair)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_socketpair)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_socketpair)))
	ALLOW_SYSCALL(socketpair),
#endif
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
#if ((SYSCALL_PREFIX == 0 && defined(__NR_arch_prctl)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_arch_prctl)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_arch_prctl)))
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYSCALL_NUM(arch_prctl), 0, 11),
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
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYSCALL_NUM(tgkill), 1, 0),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYSCALL_NUM(kill), 0, 10),
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
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYSCALL_NUM(mmap), 0, 6),
	EXAMINE_ARG(3),  /* flags */
	BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, MAP_ANONYMOUS, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, ~(VALID_MAP_FLAGS), 0, 1),
	FAIL_ECAPMODE,
	ALLOW,

#if ((SYSCALL_PREFIX == 0 && defined(__NR_mmap2)) || \
     (SYSCALL_PREFIX == 1 && defined(__NR_amd64_mmap2)) || \
     (SYSCALL_PREFIX == 2 && defined(__NR_ia32_mmap2)))
	/* mmap2(2) */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYSCALL_NUM(mmap2), 0, 6),
	EXAMINE_ARG(3),  /* flags */
	BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, MAP_ANONYMOUS, 0, 1),
	ALLOW,
	BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, ~(VALID_MAP_FLAGS), 0, 1),
	FAIL_ECAPMODE,
	ALLOW,
#endif

	/* openat(2) */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYSCALL_NUM(openat), 0, 7),
	EXAMINE_ARG(0),  /* dfd */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AT_FDCWD, 0, 1),
	FAIL_ECAPMODE,
	EXAMINE_ARG(2),  /* flags */
	BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, ~(VALID_OPENAT_FLAGS), 0, 1),
	FAIL_ECAPMODE,
	ALLOW,

	/* prctl(2) */
#ifdef PR_GET_OPENAT_BENEATH
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYSCALL_NUM(prctl), 0, 36),
#else
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYSCALL_NUM(prctl), 0, 34),
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

#ifdef WCLONEFD
	/* wait4(2) */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYSCALL_NUM(wait4), 0, 4),
	EXAMINE_ARG(2),  /* options */
	BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, WCLONEFD, 1, 0),
	FAIL_ECAPMODE,
	ALLOW,
#endif

#if (SYSCALL_ARCH == ARCH_X86_64 && defined(__NR_x32_rt_sigaction))
	ALLOW_X32_SYSCALL(rt_sigaction),
#endif
#if (SYSCALL_ARCH == ARCH_X86_64 && defined(__NR_x32_rt_sigreturn))
	ALLOW_X32_SYSCALL(rt_sigreturn),
#endif
#if (SYSCALL_ARCH == ARCH_X86_64 && defined(__NR_x32_ioctl))
	ALLOW_X32_SYSCALL(ioctl),
#endif
#if (SYSCALL_ARCH == ARCH_X86_64 && defined(__NR_x32_readv))
	ALLOW_X32_SYSCALL(readv),
#endif
#if (SYSCALL_ARCH == ARCH_X86_64 && defined(__NR_x32_writev))
	ALLOW_X32_SYSCALL(writev),
#endif
#if (SYSCALL_ARCH == ARCH_X86_64 && defined(__NR_x32_recvfrom))
	ALLOW_X32_SYSCALL(recvfrom),
#endif
#if (SYSCALL_ARCH == ARCH_X86_64 && defined(__NR_x32_sendmsg))
	ALLOW_X32_SYSCALL(sendmsg),
#endif
#if (SYSCALL_ARCH == ARCH_X86_64 && defined(__NR_x32_recvmsg))
	ALLOW_X32_SYSCALL(recvmsg),
#endif
#if (SYSCALL_ARCH == ARCH_X86_64 && defined(__NR_x32_rt_sigpending))
	ALLOW_X32_SYSCALL(rt_sigpending),
#endif
#if (SYSCALL_ARCH == ARCH_X86_64 && defined(__NR_x32_rt_sigtimedwait))
	ALLOW_X32_SYSCALL(rt_sigtimedwait),
#endif
#if (SYSCALL_ARCH == ARCH_X86_64 && defined(__NR_x32_rt_sigqueueinfo))
	ALLOW_X32_SYSCALL(rt_sigqueueinfo),
#endif
#if (SYSCALL_ARCH == ARCH_X86_64 && defined(__NR_x32_sigaltstack))
	ALLOW_X32_SYSCALL(sigaltstack),
#endif
#if (SYSCALL_ARCH == ARCH_X86_64 && defined(__NR_x32_mq_notify))
	ALLOW_X32_SYSCALL(mq_notify),
#endif
#if (SYSCALL_ARCH == ARCH_X86_64 && defined(__NR_x32_vmsplice))
	ALLOW_X32_SYSCALL(vmsplice),
#endif
#if (SYSCALL_ARCH == ARCH_X86_64 && defined(__NR_x32_preadv))
	ALLOW_X32_SYSCALL(preadv),
#endif
#if (SYSCALL_ARCH == ARCH_X86_64 && defined(__NR_x32_pwritev))
	ALLOW_X32_SYSCALL(pwritev),
#endif
#if (SYSCALL_ARCH == ARCH_X86_64 && defined(__NR_x32_rt_tgsigqueueinfo))
	ALLOW_X32_SYSCALL(rt_tgsigqueueinfo),
#endif
#if (SYSCALL_ARCH == ARCH_X86_64 && defined(__NR_x32_recvmmsg))
	ALLOW_X32_SYSCALL(recvmmsg),
#endif
#ifdef __NR_X32_sendmmsg
	ALLOW_X32_SYSCALL(sendmmsg),
#endif
#if (SYSCALL_ARCH == ARCH_X86_64 && defined(__NR_x32_setsockopt))
	ALLOW_X32_SYSCALL(setsockopt),
#endif
#if (SYSCALL_ARCH == ARCH_X86_64 && defined(__NR_x32_getsockopt))
	ALLOW_X32_SYSCALL(getsockopt),
#endif
#if (SYSCALL_ARCH == ARCH_X86_64 && defined(__NR_x32_execveat))
	ALLOW_X32_SYSCALL(execveat),
#endif

	/* Fail everything else */
	FAIL_ECAPMODE,
};
