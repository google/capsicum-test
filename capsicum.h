/*
 * Tests for Capsicum, a capability API for UNIX.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef __CAPSICUM_H__
#define __CAPSICUM_H__

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

// Map umount2 (Linux) syscall to unmount (FreeBSD) syscall
#define umount2(T, F) unmount(T, F)

// Map sighandler_y (Linux) to sig_t (FreeBSD)
#define sighandler_t sig_t

#include <sys/uio.h>
inline ssize_t sendfile_(int out_fd, int in_fd, off_t *offset, size_t count) {
  return sendfile(in_fd, out_fd, *offset, count, NULL, offset, 0);
}

// FreeBSD has getdents(2) available
#include <sys/types.h>
#include <dirent.h>
inline int getdents_(unsigned int fd, void *dirp, unsigned int count) {
  return getdents(fd, (char*)dirp, count);
}
#include <sys/mman.h>
inline int mincore_(void *addr, size_t length, unsigned char *vec) {
  return mincore(addr, length, (char*)vec);
}

// Features available
#define HAVE_CHFLAGS
#define HAVE_GETFSSTAT
#define HAVE_REVOKE
#define HAVE_GETLOGIN
#define HAVE_SYSARCH
#include <machine/sysarch.h>
#define HAVE_STAT_BIRTHTIME
#define HAVE_SYSCTL
#define HAVE_FPATHCONF
// FreeBSD polices FD rights even before capability mode is entered.
#define HAVE_RIGHTS_CHECK_OUTSIDE_CAPMODE
// FreeBSD only allows root to call mlock[all]/munlock[all]
#define MLOCK_REQUIRES_ROOT 1
// FreeBSD effectively only allows root to call sched_setscheduler
#define SCHED_SETSCHEDULER_REQUIRES_ROOT 1

#endif

#ifdef __linux__
/* Linux definitions */
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/sendfile.h>
#include <errno.h>
#include <linux/seccomp.h>

/* TODO(drysdale): get at properly exported versions */
#include "capsicum_caps.h"

#define HAVE_DUP3
#define HAVE_PIPE2
#include <sys/fsuid.h>  /* for setfsgid()/setfsuid() */
#define HAVE_SETFSUID
#define HAVE_SETFSGID
// Linux allows anyone to call mlock[all]/munlock[all]
#define MLOCK_REQUIRES_ROOT 0
// Linux allows anyone to call sched_setscheduler
#define SCHED_SETSCHEDULER_REQUIRES_ROOT 1

#define PD_DAEMON       0x01

#ifdef __cplusplus
extern "C" {
#endif
inline int getdents_(unsigned int fd, void *dirp, unsigned int count) {
  return syscall(__NR_getdents, fd, dirp, count);
}
#define mincore_ mincore
#define sendfile_ sendfile

inline int cap_enter() {
  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_CAPSICUM);
}

inline int cap_getmode(unsigned int *mode) {
  int rc = prctl(PR_GET_SECCOMP);
  if (rc < 0) return rc;
  *mode = (rc == SECCOMP_MODE_CAPSICUM);
  return 0;
}

typedef unsigned long cap_rights_t;

inline int cap_new(int fd, cap_rights_t rights) {
  return syscall(__NR_cap_new, fd, rights);
}

inline int cap_getrights(int fd, cap_rights_t *rights) {
  return syscall(__NR_cap_getrights, fd, rights);
}

// Linux glibc includes an fexecve() function, implemented via the /proc
// filesystem.  Bypass this and go directly to the fexecve syscall.
// TODO(drysdale): replace fexecve() implementation
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
