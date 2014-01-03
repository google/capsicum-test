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

#include "capsicum.h"

int main(int argc, char *argv[]) {
  int lifetime = 4; /* seconds */
  if (1 < argc) {
    lifetime = atoi(argv[1]);
  }

  int fd = dup(STDOUT_FILENO);
  fprintf(stderr, "fd=%d\n", fd);

  /* cap_new() available? */
  int cap_fd = cap_new(fd, CAP_READ|CAP_WRITE|CAP_SEEK);
  fprintf(stderr, "cap_fd=%d\n", cap_fd);
  if (cap_fd < 0) fprintf(stderr, "cap_new() failed: errno=%d %s\n", errno, strerror(errno));

  /* cap_getrights() available? */
  cap_rights_t rights;
  int rc = cap_getrights(cap_fd, &rights);
  fprintf(stderr, "cap_getrights(cap_fd=%d) rc=%d rights=0x%016llx\n", cap_fd, rc, rights);
  if (rc < 0) fprintf(stderr, "cap_getrights() failed: errno=%d %s\n", errno, strerror(errno));

  /* pdfork() available? */
  int pd = -1;
  rc = pdfork(&pd, 0);
  fprintf(stderr, "[%d] pdfork() rc=%d pd=%d\n", getpid(), rc, pd);
  if (rc < 0) fprintf(stderr, "pdfork() failed: errno=%d %s\n", errno, strerror(errno));

  if (rc == 0) { /* child */
    int count = 0;
    while (count < 20) {
      fprintf(stderr, "[%d] child alive, parent is ppid=%d\n", getpid(), getppid());
      sleep(1);
    }
    fprintf(stderr, "[%d] child exit(0)\n", getpid());
    exit(0);
  }

  /* pdgetpid() available? */
  pid_t actual_pid = rc;
  pid_t got_pid = -1;
  rc = pdgetpid(pd, &got_pid);
  if (rc < 0) fprintf(stderr, "pdgetpid(pd=%d) failed: errno=%d %s\n", pd, errno, strerror(errno));
  fprintf(stderr, "pdgetpid(pd=%d)=%d, pdfork returned %d\n", pd, got_pid, actual_pid);

  sleep(lifetime);
  /* pdkill() available? */
  rc = pdkill(pd, SIGKILL);
  fprintf(stderr, "[%d] pdkill(pd=%d, SIGKILL) -> rc=%d\n", getpid(), pd, rc);
  if (rc < 0) fprintf(stderr, "pdkill() failed: errno=%d %s\n", errno, strerror(errno));

  fprintf(stderr, "[%d] forking off a child process to check cap_enter()\n", getpid());
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
    fprintf(stderr, "[%d] about to fexecve('/bin/ls')\n", getpid());
    rc = fexecve(ls_bin, argv_pass, null_envp);
    /* should never reach here */
    fprintf(stderr, "[%d] fexecve(fd=%d, ...) -> rc=%d\n", getpid(), ls_bin, rc);
    if (rc < 0) fprintf(stderr, "fexecve() failed: errno=%d %s\n", errno, strerror(errno));
  }

  return 0;
}
