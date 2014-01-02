/*
 * Minimal portability layer for Capsicum-related features.
 */
#ifndef __CAPSICUM_H__
#define __CAPSICUM_H__

/************************************************************
 * FreeBSD
 ************************************************************/
#ifdef __FreeBSD__

#ifdef __cplusplus
extern "C" {
#endif

/* FreeBSD definitions */
#include <sys/capability.h>
#include <sys/procdesc.h>

#ifdef __cplusplus
}
#endif

// Use fexecve_() in tests to allow Linux variant to bypass glibc version.
#define fexecve_(F, A, E) fexecve(F, A, E)

// FreeBSD treats CAP_MASK_VALID exactly like a non-capability
#define CAP_MASK_VALID_IS_UNCHECKED 1

#endif

/************************************************************
 * FreeBSD
 ************************************************************/
#ifdef __linux__
/* Linux definitions */
#include <errno.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/capsicum.h>
#include <linux/procdesc.h>

#define HAVE_PDWAIT4
// Linux treats a capability with CAP_MASK_VALID differently than a non-capability
#define CAP_MASK_VALID_IS_UNCHECKED 0

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CAP_FSIGNAL
#define CAP_FSIGNAL   0x0080000000000000ULL
#endif
#ifndef CAP_EPOLL_CTL
#define CAP_EPOLL_CTL 0x0100000000000000ULL
#endif
#ifndef CAP_NOTIFY
#define CAP_NOTIFY    0x0200000000000000ULL
#endif
#ifndef CAP_SETNS
#define CAP_SETNS     0x0400000000000000ULL
#endif

inline int cap_enter() {
  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_CAPSICUM);
}

inline int cap_getmode(unsigned int *mode) {
  int rc = prctl(PR_GET_SECCOMP);
  if (rc < 0) return rc;
  *mode = (rc == SECCOMP_MODE_CAPSICUM);
  return 0;
}

inline int cap_new(int fd, cap_rights_t rights) {
  return syscall(__NR_cap_new, fd, rights);
}

inline int cap_getrights(int fd, cap_rights_t *rights) {
  return syscall(__NR_cap_getrights, fd, rights);
}

// Linux glibc includes an fexecve() function, implemented via the /proc
// filesystem.  Bypass this and go directly to the fexecve syscall.
inline int fexecve_(int fd, char **argv, char **envp)
{
  return syscall(__NR_fexecve, fd, argv, envp);
}

inline int pdfork(int *fd, int flags) {
  return syscall(__NR_pdfork, fd, flags);
}

inline int pdgetpid(int fd, pid_t *pid) {
  return syscall(__NR_pdgetpid, fd, pid);
}

inline int pdkill(int fd, int signum) {
  return syscall(__NR_pdkill, fd, signum);
}

inline int pdwait4(int fd, int *status, int options, struct rusage *rusage) {
  return syscall(__NR_pdwait4, fd, status, options, rusage);
}

#ifdef __cplusplus
}
#endif

#endif

#endif /*__CAPSICUM_H__*/
