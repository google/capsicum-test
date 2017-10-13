/* seccomp-BPF implementation of capability mode */
#ifdef __linux__
#define _GNU_SOURCE  /* to get O_* constants */
#include "config.h"
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <syscall.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/fcntl.h>
#include <linux/filter.h>
#include <linux/net.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <linux/wait.h>
#include <asm/prctl.h>
#ifdef HAVE_ASM_UNISTD_64_AMD64_H
#include <asm/unistd_64_amd64.h>  /* defines __NR_amd64_<name> values */
#endif
#ifdef HAVE_ASM_UNISTD_64_X32_H
#include <asm/unistd_64_x32.h>  /* defines __NR_x32_<name> values */
#endif
#ifdef HAVE_ASM_UNISTD_32_IA32_H
#include <asm/unistd_32_ia32.h>  /* defines __NR_ia32_<name> values */
#endif

/* Macros for BPF generation */

#define COUNT_OF(x) (sizeof(x)/sizeof(0[x]))

/*
 * x32 ABI syscalls have a high bit set; remove this in all comparisons, so that
 * the a filter built for x86_64 (but including the __NR_x32_* additional
 * values) can be used for both x86_64 and x32 ABI programs.
 */
#ifdef  __X32_SYSCALL_BIT
#define SYSCALL_NUM_MASK	(~__X32_SYSCALL_BIT)
#else
#define SYSCALL_NUM_MASK	(~0)
#endif

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
#define ALLOW_SYSCALL_NUM(num)	\
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (num & SYSCALL_NUM_MASK), 0, 1),	\
	ALLOW
#define ALLOW_SYSCALL(name)		ALLOW_SYSCALL_NUM(SYSCALL_NUM(name))
#define SYSCALL_X32_NUM(name)		(__NR_x32_##name & SYSCALL_NUM_MASK)
#define ALLOW_X32_SYSCALL(name)	ALLOW_SYSCALL_NUM(SYSCALL_X32_NUM(name))
#define FAIL_ECAPMODE	\
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | (ECAPMODE & 0xFFFF))

#ifdef SECCOMP_DATA_TID_PRESENT
/* Build environment includes .tgid and .tid fields in seccomp_data */
#define EXAMINE_TGID	\
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, tgid))
#define EXAMINE_TID	\
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, tid))
#endif

/*
 * Check a dfd at argument n is not AT_FDCWD.  Only check the low 32-bits to
 * avoid sign-extension problems.
 */
#define FAIL_AT_FDCWD(n)					\
	EXAMINE_ARG(n),  /* dfd */				\
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AT_FDCWD, 0, 1),	\
	FAIL_ECAPMODE
#define FAIL_AT_FDCWD_COUNT 3

#define ALLOW_AT_SYSCALL_NUM(num, arg)					\
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (num & SYSCALL_NUM_MASK), 0, 1+FAIL_AT_FDCWD_COUNT),	\
	FAIL_AT_FDCWD(arg),					\
	ALLOW
#define ALLOW_AT_SYSCALL_ARG(name, arg)	ALLOW_AT_SYSCALL_NUM(SYSCALL_NUM(name), arg)
#define ALLOW_AT_SYSCALL(name)			ALLOW_AT_SYSCALL_NUM(SYSCALL_NUM(name), 0)
#define ALLOW_X32_AT_SYSCALL(name)		ALLOW_AT_SYSCALL_NUM(SYSCALL_X32_NUM(name), 0)
#define ALLOW_2AT_SYSCALL_NUM(num, arg1, arg2)				\
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (num & SYSCALL_NUM_MASK), 0, 1+FAIL_AT_FDCWD_COUNT+FAIL_AT_FDCWD_COUNT),	\
	FAIL_AT_FDCWD(arg1),					\
	FAIL_AT_FDCWD(arg2),					\
	ALLOW
#define ALLOW_AT_SYSCALL_2ARG(name, a1, a2)	ALLOW_2AT_SYSCALL_NUM(SYSCALL_NUM(name), a1, a2)

/*
 * Create a filter for our base architecture by including the filter header
 * with the following macros set:
 *   - SYSCALL_NUM(name) : use constants of form __NR_<name>
 *   - SYSCALL_PREFIX : use 0 to indicate no prefix
 *   - SYSCALL_ARCH : current build architecture
 *   - SYSCALL_FILTER : capmode_filter
 */
#if defined(__i386__)
#define BASE_ARCH	AUDIT_ARCH_I386
#elif defined(__x86_64__)
/* Note: x86_64 also includes x32 ABI */
#define BASE_ARCH	AUDIT_ARCH_X86_64
#else
#error "Platform does not support seccomp filter yet"
#endif

/*
 * Provide definition of:
 *   static struct sock_filter capmode_filter[];
 */
#define SYSCALL_ARCH		BASE_ARCH
#define SYSCALL_NUM(name)	(__NR_##name & SYSCALL_NUM_MASK)
#define SYSCALL_PREFIX		0
#define SYSCALL_FILTER		capmode_filter
#include "linux-bpf-capmode.h"
#undef SYSCALL_ARCH
#undef SYSCALL_NUM
#undef SYSCALL_PREFIX
#undef SYSCALL_FILTER

/* Now see if we can build a filter for the alternate architecture. */

#if defined(__i386__)
/* Building on 32-bit, see if we have definitions for amd64 syscall numbers */
#define ALT_ARCH	AUDIT_ARCH_X86_64
#ifdef HAVE_ASM_UNISTD_64_AMD64_H
#define SYSCALL_NUM(name)	(__NR_amd64_##name & SYSCALL_NUM_MASK)
#define SYSCALL_PREFIX		1
#define HAVE_ALTFILTER
#endif
#elif defined(__x86_64__)
/* Building on 64-bit or x32, see if we have definitions for ia32/i386 syscall numbers */
#define ALT_ARCH	AUDIT_ARCH_I386
#ifdef HAVE_ASM_UNISTD_64_AMD64_H
#define SYSCALL_NUM(name)	(__NR_ia32_##name & SYSCALL_NUM_MASK)
#define SYSCALL_PREFIX		2
#define HAVE_ALTFILTER
#endif
#endif

#ifdef HAVE_ALTFILTER
/*
 * Create a filter for our alternate architecture by including the filter header
 * with the following macros set:
 *      build arch:             amd64                       i386
 *  SYSCALL_NUM(name)      __NR_ia32_<name>            __NR_amd64_<name>
 *  SYSCALL_PREFIX             2 (=>ia32)                  1 (=>amd64)
 *  SYSCALL_ARCH            AUDIT_ARCH_I386            AUDIT_ARCH_X86_64
 *  SYSCALL_FILTER          capmode_altfilter          capmode_altfilter
 */

/*
 * Provide definition of:
 *   static struct sock_filter capmode_altfilter[];
 */
#define SYSCALL_ARCH		ALT_ARCH
#define SYSCALL_FILTER		capmode_altfilter
#include "linux-bpf-capmode.h"
#undef SYSCALL_ARCH
#undef SYSCALL_NUM
#undef SYSCALL_PREFIX
#undef SYSCALL_FILTER
#endif

#ifdef HAVE_ALTFILTER
/* With two possible architectures in play, need to select appropriately. */
static struct sock_filter capmode_combifilter[3+COUNT_OF(capmode_filter)+COUNT_OF(capmode_altfilter)] = {
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)), /* load arch */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, BASE_ARCH, 1, 0),
	BPF_JUMP(BPF_JMP+BPF_JA, COUNT_OF(capmode_filter), 0, 0),
	/* capmode_filter contents */
	/* capmode_altfilter contents */
};
static void __attribute__((constructor)) _filter_init(void) {
	int ii;
	int offset = 3;
	for (ii = 0; ii < COUNT_OF(capmode_filter); ii++)
		capmode_combifilter[offset + ii] = capmode_filter[ii];
	offset += COUNT_OF(capmode_filter);
	for (ii = 0; ii < COUNT_OF(capmode_altfilter); ii++)
		capmode_combifilter[offset + ii] = capmode_altfilter[ii];
}
static struct sock_fprog capmode_fprog = {
	.len = (3 + COUNT_OF(capmode_filter) + COUNT_OF(capmode_altfilter)),
	.filter = capmode_combifilter
};
#else
/* If only a single arch is available, just run the base filter */
static struct sock_fprog capmode_fprog = {
	.len = COUNT_OF(capmode_filter),
	.filter = capmode_filter
};
#endif

#ifdef UNUSED
static void print_filter(struct sock_fprog *bpf) {
	int pc;
	printf(" line  OP   JT   JF   K\n");
	printf("=================================\n");
	for (pc = 0; pc < bpf->len; pc++) {
		struct sock_filter *filter = &(bpf->filter[pc]);
		printf(" %04d: 0x%02x 0x%02x 0x%02x 0x%08x\n",
			pc, filter->code, filter->jt, filter->jf, filter->k);
	}
}
#endif

int seccomp_(unsigned int op, unsigned int flags, struct sock_fprog *filter) {
	errno = 0;
	return syscall(__NR_seccomp, op, flags, filter, 0, 0, 0);
}

int cap_enter() {
	int rc;

	rc = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (rc < 0) return rc;

#ifdef PR_SET_OPENAT_BENEATH
	rc = prctl(PR_SET_OPENAT_BENEATH, 1 , PR_SET_OPENAT_BENEATH_TSYNC, 0, 0);
	if (rc < 0) return rc;
#else
	/* If PR_SET_OPENAT_BENEATH is unavailable, capability mode is not possible */
	errno = ENOSYS;
	return -1;
#endif
	return seccomp_(SECCOMP_SET_MODE_FILTER,
			SECCOMP_FILTER_FLAG_TSYNC,
			&capmode_fprog);
}

int cap_getmode(unsigned int *mode) {
	int beneath;
	int seccomp;

#ifdef PR_GET_OPENAT_BENEATH
	beneath = prctl(PR_GET_OPENAT_BENEATH, 0, 0, 0, 0);
	if (beneath < 0) return beneath;
#else
	errno = ENOSYS;
	return -1;
#endif

	seccomp = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
	if (seccomp < 0) return seccomp;
	*mode = (seccomp == SECCOMP_MODE_FILTER && beneath == 1);
	return 0;
}

bool cap_sandboxed(void) {
	unsigned int mode;
	if (cap_getmode(&mode) != 0) return false;
	return (mode == 1);
}

#endif /* __linux__ */
