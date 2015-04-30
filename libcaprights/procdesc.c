#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/sched.h>
#include "procdesc.h"

extern const int sigchld_num;  /* = SIGCHLD */

#ifdef __NR_clone4

int pdfork(int *fd, int flags) {
  struct clone4_args args;
  __u64 clone_flags = CLONE_FD;

  if (flags & ~(PD_DAEMON|PD_CLOEXEC|PD_GENERATE_SIGCHLD)) {
    errno = EINVAL;
    return -1;
  }
  memset(&args, 0, sizeof(args));
  args.clonefd = fd;
  if (!(flags & PD_DAEMON)) {
    args.clonefd_flags |= CLONEFD_KILL_ON_CLOSE;
  }
  if (!(flags & PD_CLOEXEC)) {
    args.clonefd_flags |= CLONEFD_CLOEXEC;
  }
  if (flags & PD_GENERATE_SIGCHLD) {
    clone_flags |= sigchld_num;
  }
  errno = 0;
  return syscall(__NR_clone4,
                 (int)(clone_flags >> 32), (int)(clone_flags & 0xFFFFFFFF),
                 (unsigned int)sizeof(args), &args, 0, 0);
}

int pdgetpid(int fd, pid_t *pid) {
  if (pid == NULL) {
    errno = EFAULT;
    return -1;
  }
  pid_t rc = ioctl(fd, CLONEFD_IOC_GETPID, 0);
  if (rc >= 0) {
    *pid = rc;
    return 0;
  } else {
    if (errno == ENOENT) {
      errno = ECHILD;
    }
    return -1;
  }
}

int pdkill(int fd, int signum) {
  unsigned char sigbyte = signum;
  int rc = write(fd, &sigbyte, sizeof(sigbyte));
  return (rc == 1) ? 0 : -1;
}

#else

/* If clone4(2) is unavailable, process descriptor functionality is unavailable */
int pdfork(int *fd, int flags) {
  errno = ENOSYS;
  return -1;
}
int pdgetpid(int fd, pid_t *pid) {
  errno = ENOSYS;
  return -1;
}
int pdkill(int fd, int signum) {
  errno = ENOSYS;
  return -1;
}

#endif
