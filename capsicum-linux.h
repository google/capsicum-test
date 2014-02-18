#ifndef __CAPSICUM_LINUX_H__
#define __CAPSICUM_LINUX_H__

#ifdef __linux__
/************************************************************
 * Linux Capsicum Functionality.
 ************************************************************/
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
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


/************************************************************
 * Capsicum System Calls.
 ************************************************************/
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

/************************************************************
 * Capsicum Rights Manipulation Functions.
 ************************************************************/

/*
 * Variadic macros (requiring C99/C++11) to invoke underlying varargs functions
 * without need for terminating zero.
 */
#define cap_rights_init(...)						\
	_cap_rights_init(CAP_RIGHTS_VERSION, __VA_ARGS__, 0ULL)
#define cap_rights_set(rights, ...)					\
	_cap_rights_set((rights), __VA_ARGS__, 0ULL)
#define cap_rights_clear(rights, ...)					\
	_cap_rights_clear((rights), __VA_ARGS__, 0ULL)
#define cap_rights_is_set(rights, ...)					\
	_cap_rights_is_set((rights), __VA_ARGS__, 0ULL)

cap_rights_t *_cap_rights_init(int version, cap_rights_t *rights, ...);
void _cap_rights_set(cap_rights_t *rights, ...);
void _cap_rights_clear(cap_rights_t *rights, ...);
bool _cap_rights_is_set(const cap_rights_t *rights, ...);

bool cap_rights_is_valid(const cap_rights_t *rights);
void cap_rights_merge(cap_rights_t *dst, const cap_rights_t *src);
void cap_rights_remove(cap_rights_t *dst, const cap_rights_t *src);
bool cap_rights_contains(const cap_rights_t *big, const cap_rights_t *little);

#ifdef __cplusplus
}
#endif

#endif /* __linux__ */

#endif /*__CAPSICUM_LINUX_H__*/
