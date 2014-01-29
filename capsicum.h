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
#include <sys/param.h>
#include <sys/capability.h>
#include <sys/procdesc.h>

#ifdef __cplusplus
}
#endif

// Use fexecve_() in tests to allow Linux variant to bypass glibc version.
#define fexecve_(F, A, E) fexecve(F, A, E)

// TODO(FreeBSD): uncomment if/when FreeBSD propagates rights on accept.
// FreeBSD does not generate a capability from accept(cap_fd,...)
// #define CAP_FROM_ACCEPT

#endif

/************************************************************
 * Linux
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
// TODO(drysdale): uncomment if/when FreeBSD propagates rights on accept.
// Linux does not generate a capability from accept(cap_fd,...)
// #define CAP_FROM_ACCEPT

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


#ifndef CAP_RIGHTS_VERSION
/* Old-style (FreeBSD 9.x) Capsicum API */
#define OLD_CAP_RIGHTS_T
#endif


#ifdef OLD_CAP_RIGHTS_T
/************************************************************
 * Capsicum compatibility layer: implement new (FreeBSD10.x)
 * API in terms of original (FreeBSD9.x) functionality.
 ************************************************************/
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

/* Rights manipulation macros/functions */
#define cap_rights_init(rights, ...)   _cap_rights_init((rights), __VA_ARGS__, 0ULL)
#define cap_rights_set(rights, ...)    _cap_rights_set((rights), __VA_ARGS__, 0ULL)
#define cap_rights_clear(rights, ...)  _cap_rights_clear((rights), __VA_ARGS__, 0ULL)
#define cap_rights_is_set(rights, ...) _cap_rights_is_set((rights), __VA_ARGS__, 0ULL)

inline cap_rights_t* _cap_rights_init(cap_rights_t *rights, ...) {
  va_list ap;
  cap_rights_t right;
  *rights = 0;
  va_start(ap, rights);
  while (true) {
    right = va_arg(ap, cap_rights_t);
    *rights |= right;
    if (right == 0) break;
  }
  va_end(ap);
  return rights;
}

inline cap_rights_t* _cap_rights_set(cap_rights_t *rights, ...) {
  va_list ap;
  cap_rights_t right;
  va_start(ap, rights);
  while (true) {
    right = va_arg(ap, cap_rights_t);
    *rights |= right;
    if (right == 0) break;
  }
  va_end(ap);
  return rights;
}

inline cap_rights_t* _cap_rights_clear(cap_rights_t *rights, ...) {
  va_list ap;
  cap_rights_t right;
  va_start(ap, rights);
  while (true) {
    right = va_arg(ap, cap_rights_t);
    *rights &= ~right;
    if (right == 0) break;
  }
  va_end(ap);
  return rights;
}

inline bool _cap_rights_is_set(const cap_rights_t *rights, ...) {
  va_list ap;
  cap_rights_t right;
  cap_rights_t accumulated = 0;
  va_start(ap, rights);
  while (true) {
    right = va_arg(ap, cap_rights_t);
    accumulated |= right;
    if (right == 0) break;
  }
  va_end(ap);
  return (accumulated & *rights) == accumulated;
}

inline bool _cap_rights_is_valid(const cap_rights_t *rights) {
  return true;
}

inline cap_rights_t* cap_rights_merge(cap_rights_t *dst, const cap_rights_t *src) {
  *dst |= *src;
  return dst;
}

inline cap_rights_t* cap_rights_remove(cap_rights_t *dst, const cap_rights_t *src) {
  *dst &= ~(*src);
  return dst;
}

inline bool cap_rights_contains(const cap_rights_t *big, const cap_rights_t *little) {
  return ((*big) & (*little)) == (*little);
}

inline void cap_rights_describe(const cap_rights_t *rights, char *buffer) {
  sprintf(buffer, "0x%016llx", (*rights));
}

/* Core functionality */
inline int cap_rights_limit(int fd, const cap_rights_t *rights) {
  int cap = cap_new(fd, *rights);
  if (cap < 0) return cap;
  return dup2(cap, fd);
}

inline int cap_rights_get(int fd, cap_rights_t *rights) {
  return cap_getrights(fd, rights);
}

#define CAP_PREAD CAP_READ
#define CAP_PWRITE CAP_WRITE
#define CAP_MMAP_X CAP_MAPEXEC
#define CAP_MKDIRAT CAP_MKDIR
#define CAP_UNLINKAT CAP_RMDIR
#define CAP_MKFIFOAT CAP_MKFIFO
#define CAP_SOCK_CLIENT \
        (CAP_CONNECT | CAP_GETPEERNAME | CAP_GETSOCKNAME | CAP_GETSOCKOPT | \
         CAP_PEELOFF | CAP_READ | CAP_WRITE | CAP_SETSOCKOPT | CAP_SHUTDOWN)
#define CAP_SOCK_SERVER \
        (CAP_ACCEPT | CAP_BIND | CAP_GETPEERNAME | CAP_GETSOCKNAME | \
         CAP_GETSOCKOPT | CAP_LISTEN | CAP_PEELOFF | CAP_READ | CAP_WRITE | \
         CAP_SETSOCKOPT | CAP_SHUTDOWN)
#define CAP_SEEK_ASWAS CAP_SEEK

#else

/* New-style Capsicum API extras */
#define CAP_SEEK_ASWAS 0

#include <stdio.h>
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
#endif

#endif /*__CAPSICUM_H__*/
