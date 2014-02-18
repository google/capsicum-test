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
#define HAVE_CAP_RIGHTS_LIMIT
#define HAVE_CAP_RIGHTS_GET
#define CAP_FROM_ACCEPT
#define AT_SYSCALLS_IN_CAPMODE

#ifdef __cplusplus
extern "C" {
#endif

/************************************************************
 * Capsicum System Calls.
 ************************************************************/
int cap_enter();
int cap_getmode(unsigned int *mode);
int cap_rights_limit(int fd, cap_rights_t *rights);
int cap_rights_get(int fd, cap_rights_t *rights);
int fexecve_(int fd, char **argv, char **envp);
int pdfork(int *fd, int flags);
int pdgetpid(int fd, pid_t *pid);
int pdkill(int fd, int signum);
int pdwait4(int fd, int *status, int options, struct rusage *rusage);

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
