#ifndef _SYS_PROCDESC_H
#define _SYS_PROCDESC_H

#include <unistd.h>
#include <linux/procdesc.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rusage;

/************************************************************
 * Process Descriptor System Calls.
 ************************************************************/
int pdfork(int *fd, int flags);
int pdgetpid(int fd, pid_t *pid);
int pdkill(int fd, int signum);
int pdwait4(int fd, int *status, int options, struct rusage *rusage);

#ifdef __cplusplus
}
#endif

#endif /*_SYS_PROCDESC_H*/
