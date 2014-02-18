/*
 * Minimal portability layer for Capsicum-related features.
 */
#ifndef __CAPSICUM_H__
#define __CAPSICUM_H__

#ifdef __FreeBSD__
#include "capsicum-freebsd.h"
#endif

#ifdef __linux__
#include "capsicum-linux.h"
#endif

/************************************************************
 * Define new-style rights in terms of old-style rights if
 * absent.
 ************************************************************/
#include "capsicum-rights.h"

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
#include <unistd.h>
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
