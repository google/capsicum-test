#ifndef __CAPSICUM_LINUX_H__
#define __CAPSICUM_LINUX_H__

#ifdef __linux__
/************************************************************
 * Linux Capsicum Functionality.
 ************************************************************/
#include <sys/procdesc.h>
#include <sys/capsicum.h>

#define HAVE_PDWAIT4
#define HAVE_CAP_RIGHTS_LIMIT
#define HAVE_CAP_RIGHTS_GET
#define HAVE_CAP_FCNTLS_LIMIT
#define HAVE_CAP_IOCTLS_LIMIT
#define HAVE_PROC_FDINFO
#define CAP_FROM_ACCEPT
// TODO(drysdale): uncomment if/when Linux propagates rights on sctp_peeloff.
// Linux does not generate a capability from sctp_peeloff(cap_fd,...).
// #define CAP_FROM_PEELOFF

#define AT_SYSCALLS_IN_CAPMODE

// Failure to open file due to path traversal generates EACCES
#define E_NO_TRAVERSE EACCES

#endif /* __linux__ */

#endif /*__CAPSICUM_LINUX_H__*/
