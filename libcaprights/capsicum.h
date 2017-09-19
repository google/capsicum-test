#ifndef _SYS_CAPSICUM_H
#define _SYS_CAPSICUM_H

/************************************************************
 * Linux Capsicum Functionality.
 ************************************************************/
#include <stdbool.h>
#include <stddef.h>
#include <limits.h>
#include <sys/types.h>
#include <linux/capsicum.h>

typedef struct cap_rights cap_rights_t;
/* fcntl(2) and cap_rights_limit(2) take unsigned int for fcntl cmds. */
typedef unsigned int cap_fcntl_t;
/* ioctl(2) and cap_rights_limit(2) take unsigned int for ioctl cmds. */
typedef unsigned int cap_ioctl_t;

#ifdef __cplusplus
extern "C" {
#endif

/************************************************************
 * Capsicum System Calls.
 ************************************************************/
int cap_enter(void);
int cap_getmode(unsigned int *mode);
bool cap_sandboxed(void);
int cap_rights_limit(int fd, const cap_rights_t *rights);
int cap_rights_get(int fd, cap_rights_t *rights);
int cap_fcntls_limit(int fd, cap_fcntl_t fcntls);
int cap_fcntls_get(int fd, cap_fcntl_t *fcntlsp);
int cap_ioctls_limit(int fd, const cap_ioctl_t *cmds, size_t ncmds);
ssize_t cap_ioctls_get(int fd, cap_ioctl_t *cmds, size_t maxcmds);

/************************************************************
 * Capsicum Rights Manipulation Functions.
 ************************************************************/

/*
 * Variadic macros (requiring C99/C++11) to invoke underlying varargs functions
 * without need for terminating zero.
 */
#define cap_rights_init(rights, ...)					\
	_cap_rights_init(CAP_RIGHTS_VERSION, rights, __VA_ARGS__, 0ULL)
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

#endif /*_SYS_CAPSICUM_H*/
