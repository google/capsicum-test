/*
 * Minimal portability layer for Capsicum-related features.
 */
#ifndef __CAPSICUM_H__
#define __CAPSICUM_H__
#include "capsicum-rights.h"

/************************************************************
 * FreeBSD
 ************************************************************/
#ifdef __FreeBSD__

#ifdef __cplusplus
extern "C" {
#endif

/* FreeBSD definitions */
#include <sys/param.h>
#include <sys/capability.h>
#include <sys/procdesc.h>
#if __FreeBSD_version >= 1000000
#define AT_SYSCALLS_IN_CAPMODE
#define HAVE_CAP_RIGHTS_GET
#define HAVE_CAP_RIGHTS_LIMIT
#endif

#ifdef __cplusplus
}
#endif

// Use fexecve_() in tests to allow Linux variant to bypass glibc version.
#define fexecve_(F, A, E) fexecve(F, A, E)

// TODO(FreeBSD): uncomment if/when FreeBSD propagates rights on accept.
// FreeBSD does not generate a capability from accept(cap_fd,...)
// #define CAP_FROM_ACCEPT

#endif  /* FreeBSD */

/************************************************************
 * Linux
 ************************************************************/
#ifdef __linux__
#include <errno.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/capsicum.h>
#include <linux/procdesc.h>

#define HAVE_PDWAIT4
#define CAP_FROM_ACCEPT
#define AT_SYSCALLS_IN_CAPMODE

#ifdef __cplusplus
extern "C" {
#endif

inline int cap_enter() {
  int rc = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  if (rc < 0) return rc;
  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_LSM);
}

inline int cap_getmode(unsigned int *mode) {
  int rc = prctl(PR_GET_SECCOMP);
  if (rc < 0) return rc;
  *mode = (rc == SECCOMP_MODE_LSM);
  return 0;
}

#define HAVE_CAP_RIGHTS_LIMIT
inline int cap_rights_limit(int fd, cap_rights_t *rights) {
  return syscall(__NR_cap_rights_limit, fd, rights);
}

#define HAVE_CAP_RIGHTS_GET
inline int cap_rights_get(int fd, cap_rights_t *rights) {
  return syscall(__NR_cap_rights_get, fd, rights);
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

#endif  /* Linux */

/************************************************************
 * Define new-style rights in terms of old-style rights if
 * absent.
 ************************************************************/
#ifdef CAP_PREAD
/* Existence of CAP_PREAD implies new-style CAP_SEEK semantics */
#define CAP_SEEK_ASWAS 0
#else
/* Old-style CAP_SEEK semantics */
#define CAP_SEEK_ASWAS CAP_SEEK
#define CAP_PREAD CAP_READ
#define CAP_PWRITE CAP_WRITE
#endif

#ifndef CAP_MMAP_R
#define CAP_MMAP_R CAP_READ
#define CAP_MMAP_W CAP_WRITE
#define CAP_MMAP_X CAP_MAPEXEC
#endif

#ifndef CAP_MKFIFOAT
#define CAP_MKFIFOAT CAP_MKFIFO
#endif

#ifndef CAP_MKNODAT
#define CAP_MKNODAT CAP_MKFIFOAT
#endif

#ifndef CAP_MKDIRAT
#define CAP_MKDIRAT CAP_MKDIR
#endif

#ifndef CAP_UNLINKAT
#define CAP_UNLINKAT CAP_RMDIR
#endif

#ifndef CAP_SOCK_CLIENT
#define CAP_SOCK_CLIENT \
        (CAP_CONNECT | CAP_GETPEERNAME | CAP_GETSOCKNAME | CAP_GETSOCKOPT | \
         CAP_PEELOFF | CAP_READ | CAP_WRITE | CAP_SETSOCKOPT | CAP_SHUTDOWN)
#endif

#ifndef CAP_SOCK_SERVER
#define CAP_SOCK_SERVER \
        (CAP_ACCEPT | CAP_BIND | CAP_GETPEERNAME | CAP_GETSOCKNAME | \
         CAP_GETSOCKOPT | CAP_LISTEN | CAP_PEELOFF | CAP_READ | CAP_WRITE | \
         CAP_SETSOCKOPT | CAP_SHUTDOWN)
#endif

#ifndef CAP_EVENT
#define CAP_EVENT CAP_POLL_EVENT
#endif

/************************************************************
 * Define new-style API functions in terms of old-style API
 * functions if absent.
 ************************************************************/
#ifndef HAVE_CAP_RIGHTS_GET
/* Define cap_rights_get() in terms of old-style cap_getrights() */
inline int cap_rights_get(int fd, cap_rights_t *rights) {
  return cap_getrights(fd, rights);
}
#endif

#ifndef HAVE_CAP_RIGHTS_LIMIT
/* Define cap_rights_limit() in terms of old-style cap_new() and dup2() */
inline int cap_rights_limit(int fd, const cap_rights_t *rights) {
  int cap = cap_new(fd, *rights);
  if (cap < 0) return cap;
  int rc = dup2(cap, fd);
  if (rc < 0) return rc;
  close(cap);
  return rc;
}
#endif

#include <stdio.h>
#ifdef CAP_RIGHTS_VERSION
/* New-style Capsicum API extras for debugging */
inline void cap_rights_describe(const cap_rights_t *rights, char *buffer) {
  for (int ii = 0; ii < (CAP_RIGHTS_VERSION+2); ii++) {
    int len = sprintf(buffer, "0x%016llx ", (unsigned long long)rights->cr_rights[ii]);
    buffer += len;
  }
}

#include <iostream>
#include <iomanip>
inline std::ostream& operator<<(std::ostream& os, cap_rights_t rights) {
  for (int ii = 0; ii < (CAP_RIGHTS_VERSION+2); ii++) {
    os << std::hex << std::setw(16) << std::setfill('0') << (unsigned long long)rights.cr_rights[ii] << " ";
  }
  return os;
}

#else

inline void cap_rights_describe(const cap_rights_t *rights, char *buffer) {
  sprintf(buffer, "0x%016llx", (*rights));
}

#endif  /* new/old style rights manipulation */

#endif /*__CAPSICUM_H__*/
