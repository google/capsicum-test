/* Small standalone test program to check the existence of Capsicum syscalls */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/prctl.h>

#define __NR_cap_new 314
#define __NR_pdfork 315
#define __NR_pdgetpid 316
#define __NR_pdkill 317

typedef unsigned long cap_rights_t;
#define CAP_READ                0x0000000000000001ULL   /* read/recv */
#define CAP_WRITE               0x0000000000000002ULL   /* write/send */
#define CAP_SEEK                0x0000000000000080ULL

#define SECCOMP_MODE_CAPSICUM	3 /* uses Capsicum to filter & check. */

inline int cap_enter() {
  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_CAPSICUM);
}

inline int cap_getmode(int* value) {
  int rc = prctl(PR_GET_SECCOMP);
  if (rc < 0) return rc;
  *value = (rc == SECCOMP_MODE_CAPSICUM);
  return 0;
}

int main() {
  int fd = syscall(__NR_dup, STDOUT_FILENO);
  fprintf(stderr, "fd=%d\n", fd);

  /* cap_new() available? */
  int cap_fd = syscall(__NR_cap_new, fd, CAP_READ|CAP_WRITE|CAP_SEEK);
  fprintf(stderr, "cap_fd=%d\n", cap_fd);
  if (cap_fd < 0) fprintf(stderr, "cap_new() failed: errno=%d %s\n", errno, strerror(errno));

  /* pdfork() available? */
  int pd = -1;
  int rc = syscall(__NR_pdfork, &pd, 0);
  fprintf(stderr, "[%d] pdfork() rc=%d pd=%d\n", getpid(), rc, pd);
  if (rc < 0) fprintf(stderr, "pdfork() failed: errno=%d %s\n", errno, strerror(errno));

  if (rc == 0) { /* child */
    int count = 0;
    while (count < 20) {
      fprintf(stderr, "[%d] child alive\n", getpid());
      sleep(1);
    }
    fprintf(stderr, "[%d] child exit(0)\n", getpid());
    exit(0);
  }

  /* pdgetpid() available? */
  pid_t actual_pid = rc;
  pid_t got_pid = -1;
  rc = syscall(__NR_pdgetpid, pd, &got_pid);
  if (rc < 0) fprintf(stderr, "pdgetpid(pd=%d) failed: errno=%d %s\n", pd, errno, strerror(errno));
  fprintf(stderr, "pdgetpid(pd=%d)=%d, pdfork returned %d\n", pd, got_pid, actual_pid);

  sleep(4);
  /* pdkill() available? */
  rc = syscall(__NR_pdkill, pd, SIGKILL);
  fprintf(stderr, "[%d] pdkill(pd=%d, SIGKILL) -> rc=%d\n", getpid(), pd, rc);
  if (rc < 0) fprintf(stderr, "pdkill() failed: errno=%d %s\n", errno, strerror(errno));

  if (fork() == 0) {
    /* cap_getmode() / cap_enter() available? */
    int cap_mode = -1;
    rc = cap_getmode(&cap_mode);
    fprintf(stderr, "[%d] cap_getmode() -> rc=%d, cap_mode=%d\n", getpid(), rc, cap_mode);
    if (rc < 0) fprintf(stderr, "cap_enter() failed: errno=%d %s\n", errno, strerror(errno));

    rc = cap_enter();
    fprintf(stderr, "[%d] cap_enter() -> rc=%d\n", getpid(), rc);
    if (rc < 0) fprintf(stderr, "cap_enter() failed: errno=%d %s\n", errno, strerror(errno));

    rc = cap_getmode(&cap_mode);
    fprintf(stderr, "[%d] cap_getmode() -> rc=%d, cap_mode=%d\n", getpid(), rc, cap_mode);
    if (rc < 0) fprintf(stderr, "cap_enter() failed: errno=%d %s\n", errno, strerror(errno));
  } else {
    /* fexecve() available? */
    char* argv_pass[] = {(char*)"/bin/ls", NULL};
    char* null_envp[] = {NULL};
    int ls_bin = open("/bin/ls", O_RDONLY);
    rc = fexecve(ls_bin, argv_pass, null_envp);
    /* should never reach here */
    fprintf(stderr, "[%d] fexecve(fd=%d, ...) -> rc=%d\n", getpid(), ls_bin, rc);
    if (rc < 0) fprintf(stderr, "fexecve() failed: errno=%d %s\n", errno, strerror(errno));
  }

  return 0;
}
