#ifndef __CAPSICUM_FREEBSD_H__
#define __CAPSICUM_FREEBSD_H__
#ifdef __FreeBSD__
/************************************************************
 * FreeBSD Capsicum Functionality.
 ************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/* FreeBSD definitions. */
#include <sys/param.h>
#include <sys/capability.h>
#include <sys/procdesc.h>

#if __FreeBSD_version >= 1000000
#define AT_SYSCALLS_IN_CAPMODE
#define HAVE_CAP_RIGHTS_GET
#define HAVE_CAP_RIGHTS_LIMIT
#define HAVE_CAP_FCNTLS_LIMIT
// fcntl(2) takes int, cap_fcntls_limit(2) takes uint32_t.
typedef uint32_t cap_fcntl_t;
#define HAVE_CAP_IOCTLS_LIMIT
// ioctl(2) and cap_ioctls_limit(2) take unsigned long.
typedef unsigned long cap_ioctl_t;
#endif

#ifdef __cplusplus
}
#endif

// Use fexecve_() in tests to allow Linux variant to bypass glibc version.
#define fexecve_(F, A, E) fexecve(F, A, E)

// Failure to open file due to path traversal generates ENOTCAPABLE
#define E_NO_TRAVERSE ENOTCAPABLE

// TODO(FreeBSD): uncomment if/when FreeBSD propagates rights on accept.
// FreeBSD does not generate a capability from accept(cap_fd,...).
// #define CAP_FROM_ACCEPT
// TODO(FreeBSD): uncomment if/when FreeBSD propagates rights on sctp_peeloff.
// FreeBSD does not generate a capability from sctp_peeloff(cap_fd,...).
// #define CAP_FROM_PEELOFF

#endif  /* __FreeBSD__ */

#endif /*__CAPSICUM_FREEBSD_H__*/
