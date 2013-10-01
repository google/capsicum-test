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

/* FreeBSD definitions */
#include <sys/capability.h>
#include <sys/procdesc.h>

#else

/* Linux definitions */
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>

/* TODO(drysdale): get at properly exported versions */
#include "capsicum_caps.h"

#define SECCOMP_MODE_CAPSICUM	3 /* uses Capsicum to filter & check. */

#define ECAPMODE        134     /* Not permitted in capability mode */
#define ENOTCAPABLE     135     /* Capabilities insufficient */

#define __NR_cap_new 314
#define __NR_pdfork 315
#define __NR_pdwait4 318
#define __NR_fexecve 319

#ifdef __cplusplus
extern "C" {
#endif

inline int cap_enter() {
  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_CAPSICUM);
}

inline int cap_getmode(unsigned int *mode) {
  return -1; // not yet implemented
}

typedef unsigned long cap_rights_t;

inline int cap_new(int fd, cap_rights_t rights) {
  return syscall(__NR_cap_new, fd, rights);
}

inline int cap_getrights(int fd, cap_rights_t *rights) {
  return -1; // not yet implemented
}

inline int sys_fexecve(int fd, char **argv, char **envp)
{
  return syscall(__NR_fexecve, fd, argv, envp);
}

inline int pdfork(int * fd, int flags) {
  return syscall(__NR_pdfork, fd, flags);
}
inline int pdwait4(int fd, int *status, int options, struct rusage *rusage) {
  return syscall(__NR_pdwait4, fd, status, options, rusage);
}

#ifdef __cplusplus
}
#endif

#endif

#endif /*__CAPSICUM_H__*/
