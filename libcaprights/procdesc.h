#ifndef _SYS_PROCDESC_H
#define _SYS_PROCDESC_H

#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rusage;

/* Fork a new process and generate a process descriptor for it */
int pdfork(int *fd, int flags);
#define PD_DAEMON		0x01  /* Don't SIGKILL on last close(2) */
#define PD_CLOEXEC		0x02  /* Make file descriptor O_CLOEXEC */
#define PD_WAIT_VISIBLE	0x04  /* Make child exit visible to wait4(-1,..) */
#define PD_GENERATE_SIGCHLD	PD_WAIT_VISIBLE  /* Child exit generates SIGCHLD */

/* Retrieve the pid value associated with a process descriptor. */
/* Requires CAP_PDGETPID right. */
int pdgetpid(int fd, pid_t *pid);

/* Send a signal to a process identified by process descriptor. */
/* Requires CAP_PDKILL right. */
int pdkill(int fd, int signum);

/* Wait for a process identified by a process descriptor. */
/* Requires CAP_PDWAIT right. */
pid_t pdwait4(int pd, int *status, int options, struct rusage *ru);

#ifdef __cplusplus
}
#endif

#endif /*_SYS_PROCDESC_H*/
