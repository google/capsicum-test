#ifndef __CAPSICUM_LINUX_H__
#define __CAPSICUM_LINUX_H__

#ifdef __linux__
/************************************************************
 * Linux Capsicum Functionality.
 ************************************************************/
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

#endif /* __linux__ */

#endif /*__CAPSICUM_LINUX_H__*/
