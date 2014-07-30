// Tests for the process descriptor API for Linux.
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <iomanip>

#include "capsicum.h"
#include "syscalls.h"
#include "capsicum-test.h"

static void print_rusage(FILE *f, struct rusage *ru) {
  fprintf(f, "  User CPU time=%ld.%06ld\n", ru->ru_utime.tv_sec, ru->ru_utime.tv_usec);
  fprintf(f, "  System CPU time=%ld.%06ld\n", ru->ru_stime.tv_sec, ru->ru_stime.tv_usec);
  fprintf(f, "  Max RSS=%ld\n", ru->ru_maxrss);
}

static void print_stat(FILE *f, const struct stat *stat) {
  fprintf(f,
          "{ .st_dev=%ld, st_ino=%ld, st_mode=%04o, st_nlink=%ld, st_uid=%d, st_gid=%d,\n"
          "  .st_rdev=%ld, .st_size=%ld, st_blksize=%ld, .st_block=%ld,\n  "
#ifdef HAVE_STAT_BIRTHTIME
          ".st_birthtime=%ld, "
#endif
          ".st_atime=%ld, .st_mtime=%ld, .st_ctime=%ld}\n",
          stat->st_dev, stat->st_ino, stat->st_mode, stat->st_nlink, stat->st_uid, stat->st_gid,
          stat->st_rdev, stat->st_size, stat->st_blksize, stat->st_blocks,
#ifdef HAVE_STAT_BIRTHTIME
          stat->st_birthtime,
#endif
          stat->st_atime, stat->st_mtime, stat->st_ctime);
}

TEST(Pdfork, Simple) {
  int pd = -1;
  pid_t parent = getpid_();
  int pid = pdfork(&pd, 0);
  EXPECT_OK(pid);
  if (pid == 0) {
    // Child: check pid values.
    EXPECT_EQ(-1, pd);
    EXPECT_NE(parent, getpid_());
    EXPECT_EQ(parent, getppid());
    sleep(1);
    exit(0);
  }
  usleep(100);  // ensure the child has a chance to run
  EXPECT_NE(-1, pd);
  int pid_got;
  EXPECT_OK(pdgetpid(pd, &pid_got));
  EXPECT_EQ(pid, pid_got);

  // Wait long enough for the child to exit().
  sleep(2);

  // Wait for the the child.
  int status;
  struct rusage ru;
  memset(&ru, 0, sizeof(ru));
#ifdef HAVE_PDWAIT4
  int waitrc = pdwait4(pd, &status, 0, &ru);
  EXPECT_EQ(pid, waitrc);
  if (verbose) {
    fprintf(stderr, "For pid %d:\n", pid);
    print_rusage(stderr, &ru);
  }
  // Can pdwait4(pd) repeatedly until pd is closed.
  memset(&ru, 0, sizeof(ru));
  errno = 0;
#ifdef OMIT
  // TODO(drysdale): make it so.
  waitrc = pdwait4(pd, &status, 0, &ru);
  EXPECT_EQ(pid, waitrc);
#endif
#else
  int waitrc = wait4(pid_got, &status, 0, &ru);
  EXPECT_EQ(waitrc, pid);
  if (verbose) {
    fprintf(stderr, "For pid %d:\n", pid);
    print_rusage(stderr, &ru);
  }
  // Can only wait4 once.
  memset(&ru, 0, sizeof(ru));
  errno = 0;
  waitrc = wait4(pid_got, &status, 0, &ru);
  EXPECT_EQ(-1, waitrc);
  EXPECT_EQ(ECHILD, errno);
#endif

  EXPECT_OK(close(pd));
}

// Test fixture that pdfork()s off a child process, which terminates
// when it receives anything on a pipe.
class PipePdfork : public ::testing::Test {
 public:
  PipePdfork() : pd_(-1), pid_(-1) {
    int pipes[2];
    EXPECT_OK(pipe(pipes));
    pipe_ = pipes[1];
    int parent = getpid_();
    if (verbose) fprintf(stderr, "[%d] about to pdfork()\n", getpid_());
    int rc = pdfork(&pd_, 0);
    EXPECT_OK(rc);
    if (rc == 0) {
      // Child process: blocking-read an int from the pipe then exit with that value.
      EXPECT_NE(parent, getpid_());
      EXPECT_EQ(parent, getppid());
      if (verbose) fprintf(stderr, "  [%d] child of %d waiting for value on pipe\n", getpid_(), getppid());
      read(pipes[0], &rc, sizeof(rc));
      if (verbose) fprintf(stderr, "  [%d] got value %d on pipe, exiting\n", getpid_(), rc);
      exit(rc);
    } else {
      pid_ = rc;
      usleep(100);  // ensure the child has a chance to run
    }
  }
  ~PipePdfork() {
    if (pid_ > 0) {
      kill(pid_, SIGKILL);
    }
    if (pd_ > 0) {
      close(pid_);
    }
  }
  int TerminateChild() {
    // Tell the child to exit.
    int zero = 0;
    if (verbose) fprintf(stderr, "[%d] write 0 to pipe\n", getpid_());
    return write(pipe_, &zero, sizeof(zero));
  }
 protected:
  int pd_;
  int pipe_;
  pid_t pid_;
};

// Can we poll a process descriptor?
TEST_F(PipePdfork, Poll) {
  // Poll the process descriptor, nothing happening.
  struct pollfd fdp;
  fdp.fd = pd_;
  fdp.events = POLLIN | POLLERR | POLLHUP;
  fdp.revents = 0;
  EXPECT_EQ(0, poll(&fdp, 1, 0));

  TerminateChild();

  // Poll again, should have activity on the process descriptor.
  EXPECT_EQ(1, poll(&fdp, 1, 2000));
  EXPECT_TRUE(fdp.revents & POLLHUP);

  // Poll a third time, still have POLLHUP.
  fdp.revents = 0;
  EXPECT_EQ(1, poll(&fdp, 1, 0));
  EXPECT_TRUE(fdp.revents & POLLHUP);

}

// Can multiple processes poll on the same descriptor?
TEST_F(PipePdfork, PollMultiple) {
  int rc = fork();
  EXPECT_OK(rc);
  if (rc == 0) {
    // Child: wait to give time for setup, then write to the pipe (which will
    // induce exit of the pdfork()ed process) and exit.
    sleep(1);
    TerminateChild();
    exit(0);
  }
  usleep(100);  // ensure the child has a chance to run

  // Fork again
  int doppel = fork();
  EXPECT_OK(doppel);
  // We now have:
  //   pid A: main process, here
  //   |--pid B: pdfork()ed process, blocked on read()
  //   |--pid C: fork()ed process, in sleep(1) above
  //   +--pid D: doppel process, here

  // Both A and D execute the following code.
  // First, check no activity on the process descriptor yet.
  struct pollfd fdp;
  fdp.fd = pd_;
  fdp.events = POLLIN | POLLERR | POLLHUP;
  fdp.revents = 0;
  EXPECT_EQ(0, poll(&fdp, 1, 0));

  // Now, wait (indefinitely) for activity on the process descriptor.
  // We expect:
  //  - pid C will finish its sleep, write to the pipe and exit
  //  - pid B will unblock from read(), and exit
  //  - this will generate an event on the process descriptor...
  //  - ...in both process A and process D.
  EXPECT_EQ(1, poll(&fdp, 1, 2000));
  EXPECT_TRUE(fdp.revents & POLLHUP);

  if (doppel == 0) {
    // Child: process D exits.
    exit(0);
  } else {
    // Parent: wait on process D.
    rc = 0;
    waitpid(doppel, &rc, 0);
    EXPECT_TRUE(WIFEXITED(rc));
    EXPECT_EQ(0, WEXITSTATUS(rc));
  }
}

#ifdef HAVE_PDWAIT4
// Check that exit status/rusage for a dead pdfork()ed child can be retrieved
// via any process descriptor.
TEST_F(PipePdfork, MultipleRetrieveExitStatus) {
  EXPECT_PID_ALIVE(pid_);
  int pd_copy = dup(pd_);
  EXPECT_LT(0, TerminateChild());

  int status;
  struct rusage ru;
  memset(&ru, 0, sizeof(ru));
  int waitrc = pdwait4(pd_, &status, 0, &ru);
  EXPECT_EQ(pid_, waitrc);
  if (verbose) {
    fprintf(stderr, "For pd %d -> pid %d:\n", pd_, pid_);
    print_rusage(stderr, &ru);
  }

#ifdef OMIT
  // TODO(drysdale): make it so status/rusage are held around until last pd closed.
  memset(&ru, 0, sizeof(ru));
  waitrc = pdwait4(pd_copy, &status, 0, &ru);
  EXPECT_EQ(pid_, waitrc);
  if (verbose) {
    fprintf(stderr, "For pd %d -> pid %d:\n", pd_copy, pid_);
    print_rusage(stderr, &ru);
  }
#endif
  close(pd_copy);
}
#endif

// Check whether a pdfork()ed process dies correctly when released.
// Can only check zombification.
TEST_F(PipePdfork, Release) {
  EXPECT_PID_ALIVE(pid_);
  EXPECT_LT(0, TerminateChild());
  EXPECT_PID_DEAD(pid_);
#ifdef HAVE_PDWAIT4
  int status;
  int rc = pdwait4(pd_, &status, 0, NULL);
  EXPECT_OK(rc);
  EXPECT_EQ(pid_, rc);
#endif
  pid_ = 0;
}

// Closing a normal process descriptor terminates the underlying process.
TEST_F(PipePdfork, Close) {
  EXPECT_PID_ALIVE(pid_);
  int status;
  EXPECT_EQ(0, waitpid(pid_, &status, WNOHANG));

  EXPECT_OK(close(pd_));
  EXPECT_PID_DEAD(pid_);
#ifdef HAVE_PDWAIT4
  // Having closed the process descriptor means that pdwait4(pd) now doesn't work.
  errno = 0;
  int rc = pdwait4(pd_, &status, 0, NULL);
  EXPECT_EQ(-1, rc);
  EXPECT_EQ(EBADF, errno);
#endif
  // Closing all process descriptors reaps the child.
  // TODO(drysdale): make it so
#ifndef __linux__
  EXPECT_EQ(-1, waitpid(pid_, &status, WNOHANG));
  EXPECT_EQ(ECHILD, errno);
#endif
}

TEST_F(PipePdfork, CloseLast) {
  // Child should only die when last process descriptor is closed.
  EXPECT_PID_ALIVE(pid_);
  int pd_other = dup(pd_);

  EXPECT_OK(close(pd_));

  EXPECT_PID_ALIVE(pid_);
  int status;
  EXPECT_EQ(0, waitpid(pid_, &status, WNOHANG));
#ifdef HAVE_PDWAIT4
  // Can no longer pdwait4() the closed process descriptor
  errno = 0;
  EXPECT_EQ(-1, pdwait4(pd_, &status, WNOHANG, NULL));
  EXPECT_EQ(EBADF, errno);
  // but can pdwait4() the still-open process descriptor.
  errno = 0;
  EXPECT_EQ(0, pdwait4(pd_other, &status, WNOHANG, NULL));
  EXPECT_EQ(0, errno);
#endif

  EXPECT_OK(close(pd_other));
  EXPECT_PID_DEAD(pid_);
}

TEST(Pdfork, WaitPid) {
  int pd = -1;
  int pid = pdfork(&pd, 0);
  EXPECT_OK(pid);
  if (pid == 0) {
    // Child: sleep 1 second then exit.
    sleep(1);
    exit(0);
  }
  // waitpid(pid) for an explicit pid does pick up the dead child,
  // even though it was pdfork()ed.
  int status;
  int rc = waitpid(pid, &status, 0);
  EXPECT_OK(rc);
  EXPECT_EQ(pid, rc);
}

#ifdef HAVE_PDWAIT4
TEST_F(PipePdfork, WaitPidThenPd) {
  TerminateChild();
  int status;
  // If we waitpid(pid) first...
  int rc = waitpid(pid_, &status, 0);
  EXPECT_OK(rc);
  EXPECT_EQ(pid_, rc);
#ifdef OMIT
  // TODO(drysdale): make it so
  // ...can still pdwait4(pd).  More explicitly: as long as there's an
  // open process descriptor, can still pdwait4(pd).
  errno = 0;
  rc = pdwait4(pd_, &status, 0, NULL);
  EXPECT_OK(rc);
  EXPECT_EQ(pid_, rc);
#endif
}

TEST_F(PipePdfork, WaitPdThenPid) {
  TerminateChild();
  int status;
  // If we pdwait4(pd) first...
  int rc = pdwait4(pd_, &status, 0, NULL);
  EXPECT_OK(rc);
  EXPECT_EQ(pid_, rc);
  // ...cannot subsequently waitpid(pid).
  errno = 0;
  rc = waitpid(pid_, &status, 0);
  EXPECT_EQ(-1, rc);
  EXPECT_EQ(ECHILD, errno);
}
#endif

TEST(Pdfork, InvalidFlag) {
  int pd = -1;
  int pid = pdfork(&pd, PD_DAEMON<<1);
  if (pid == 0) {
    exit(1);
  }
  EXPECT_EQ(-1, pid);
  EXPECT_EQ(EINVAL, errno);
  if (pid > 0) waitpid(pid, NULL, 0);
}

// Setting PD_DAEMON prevents close() from killing the child.
TEST(Pdfork, CloseDaemon) {
  int pd = -1;
  int pid = pdfork(&pd, PD_DAEMON);
  EXPECT_OK(pid);
  if (pid == 0) {
    // Child: loop forever.
    while (true) sleep(1);
  }
  usleep(100);  // ensure the child has a chance to run
  EXPECT_OK(close(pd));
  EXPECT_PID_ALIVE(pid);
  // Can still explicitly kill it.
  if (pid > 0) {
    EXPECT_OK(kill(pid, SIGKILL));
    EXPECT_PID_DEAD(pid);
  }
}

TEST_F(PipePdfork, Pdkill) {
  EXPECT_PID_ALIVE(pid_);
  // SIGCONT is ignored by default.
  EXPECT_OK(pdkill(pd_, SIGCONT));
  EXPECT_PID_ALIVE(pid_);
  // SIGINT isn't
  EXPECT_OK(pdkill(pd_, SIGINT));
  EXPECT_PID_DEAD(pid_);
  // pdkill() on zombie is no-op.
  errno = 0;
  EXPECT_EQ(0, pdkill(pd_, SIGINT));
  EXPECT_EQ(0, errno);
}

TEST(Pdfork, PdkillDaemon) {
  int pd = -1;
  int pid = pdfork(&pd, PD_DAEMON);
  EXPECT_OK(pid);
  if (pid == 0) {
    // Child: loop forever.
    while (true) sleep(1);
  }
  usleep(100);  // ensure the child has a chance to run
  EXPECT_PID_ALIVE(pid);
  // SIGCONT is ignored by default.
  EXPECT_OK(pdkill(pd, SIGCONT));
  EXPECT_PID_ALIVE(pid);
  // SIGINT isn't
  EXPECT_OK(pdkill(pd, SIGINT));
  EXPECT_PID_DEAD(pid);
#ifdef OMIT
  // TODO(drysdale), TODO(FreeBSD): make it so
  // Can't pdkill() an already-dead child.
  errno = 0;
  EXPECT_EQ(-1, pdkill(pd, SIGINT));
  EXPECT_EQ(ESRCH, errno);
#endif
}

static int had_signal = 0;
static void handle_signal(int x) { had_signal = 1; }

TEST(Pdfork, PdkillOtherSignal) {
  int pd = -1;
  int pid = pdfork(&pd, 0);
  EXPECT_OK(pid);
  if (pid == 0) {
    // Child: watch for SIGUSR1 forever.
    had_signal = 0;
    signal(SIGUSR1, handle_signal);
    while(!had_signal) sleep(1);
    exit(123);
  }
  // Send an expected SIGUSR1 to the pdfork()ed child.
  sleep(1);
  EXPECT_PID_ALIVE(pid);
  pdkill(pd, SIGUSR1);
  EXPECT_PID_DEAD(pid);

  // Child's exit status confirms whether it received the signal.
  int status;
  int rc = waitpid(pid, &status, 0);
  EXPECT_OK(rc);
  EXPECT_EQ(pid, rc);
  EXPECT_TRUE(WIFEXITED(status)) << "0x" << std::hex << rc;
  EXPECT_EQ(123, WEXITSTATUS(status));
}

pid_t PdforkParentDeath(int pdfork_flags) {
  // Set up:
  //   pid A: main process, here
  //   +--pid B: fork()ed process, sleep(4)s then exits
  //      +--pid C: pdfork()ed process, looping forever
  int sock_fds[2];
  EXPECT_OK(socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds));
  if (verbose) fprintf(stderr, "[%d] parent about to fork()...\n", getpid_());
  pid_t child = fork();
  EXPECT_OK(child);
  if (child == 0) {
    int pd;
    if (verbose) fprintf(stderr, "  [%d] child about to pdfork()...\n", getpid_());
    pid_t grandchild = pdfork(&pd, pdfork_flags);
    if (grandchild == 0) {
      while (true) {
        if (verbose) fprintf(stderr, "    [%d] grandchild still alive\n", getpid_());
        sleep(1);
      }
    }
    if (verbose) fprintf(stderr, "  [%d] pdfork()ed grandchild %d, sending ID to parent\n", getpid_(), grandchild);
    // send grandchild pid to parent
    write(sock_fds[1], &grandchild, sizeof(grandchild));
    sleep(4);
    if (verbose) fprintf(stderr, "  [%d] child terminating\n", getpid_());
    exit(0);
  }
  if (verbose) fprintf(stderr, "[%d] fork()ed child is %d\n", getpid_(), child);
  pid_t grandchild;
  read(sock_fds[0], &grandchild, sizeof(grandchild));
  if (verbose) fprintf(stderr, "[%d] receive grandchild id %d\n", getpid_(), grandchild);
  EXPECT_PID_ALIVE(child);
  EXPECT_PID_ALIVE(grandchild);
  sleep(6);
  // Child dies, closing its process descriptor for the grandchild.
  EXPECT_PID_DEAD(child);
  return grandchild;
}

TEST(Pdfork, Bagpuss) {
  pid_t grandchild = PdforkParentDeath(0);
  // By default: child death => closed process descriptor => grandchild death.
  EXPECT_PID_DEAD(grandchild);
}

TEST(Pdfork, BagpussDaemon) {
  pid_t grandchild = PdforkParentDeath(PD_DAEMON);
  // With PD_DAEMON: child death => closed process descriptor => no effect on grandchild.
  EXPECT_PID_ALIVE(grandchild);
  if (grandchild > 0) {
    EXPECT_OK(kill(grandchild, SIGKILL));
  }
}

// The exit of a pdfork()ed process should not generate SIGCHLD.
TEST_F(PipePdfork, NoSigchld) {
  had_signal = 0;
  sighandler_t original = signal(SIGCHLD, handle_signal);
  TerminateChild();
  int rc = 0;
  // Can waitpid() for the specific pid of the pdfork()ed child.
  EXPECT_EQ(pid_, waitpid(pid_, &rc, 0));
  EXPECT_TRUE(WIFEXITED(rc)) << "0x" << std::hex << rc;
  EXPECT_EQ(0, had_signal);
  signal(SIGCHLD, original);
}

TEST_F(PipePdfork, ModeBits) {
  // Owner rwx bits indicate liveness of child
  struct stat stat;
  memset(&stat, 0, sizeof(stat));
  EXPECT_OK(fstat(pd_, &stat));
  if (verbose) print_stat(stderr, &stat);
  EXPECT_EQ(S_IRWXU, stat.st_mode & S_IRWXU);

  TerminateChild();
  usleep(100000);

  memset(&stat, 0, sizeof(stat));
  EXPECT_OK(fstat(pd_, &stat));
  if (verbose) print_stat(stderr, &stat);
  EXPECT_EQ(0, stat.st_mode & S_IRWXU);
}

#ifdef OMIT
// TODO(FreeBSD): make wildcard wait ignore pdfork()ed children
// TODO(drysdale): make wildcard wait ignore pdfork()ed children
TEST_F(PipePdfork, WildcardWait) {
  TerminateChild();
  sleep(1);  // Ensure child is truly dead.

  // Wildcard waitpid(-1) should not see the pdfork()ed child.
  int rc;
  EXPECT_EQ(0, waitpid(-1, &rc, WNOHANG));

  int status;
  rc = waitpid(pd_, &status, 0);
  EXPECT_OK(rc);
  EXPECT_EQ(pid_, rc);
}
#endif

void CheckChildFinished(pid_t pid, bool signaled=false) {
  // Wait for the child to finish.
  int rc;
  int status = 0;
  do {
    rc = waitpid(pid, &status, 0);
    if (rc < 0) {
      fprintf(stderr, "Warning: waitpid error %s (%d)\n", strerror(errno), errno);
      ADD_FAILURE() << "Failed to wait for child";
      break;
    } else if (rc == pid) {
      break;
    }
  } while (1);
  EXPECT_EQ(pid, rc);
  if (rc == pid) {
    if (signaled) {
      EXPECT_TRUE(WIFSIGNALED(status));
    } else {
      EXPECT_TRUE(WIFEXITED(status)) << std::hex << status;
      EXPECT_EQ(0, WEXITSTATUS(status));
    }
  }
}

FORK_TEST(Pdfork, Pdkill) {
  had_signal = 0;
  int pd;
  pid_t pid = pdfork(&pd, 0);
  EXPECT_OK(pid);

  if (pid == 0) {
    // Child: set a SIGINT handler and sleep.
    had_signal = 0;
    signal(SIGINT, handle_signal);
    if (verbose) fprintf(stderr, "[%d] child about to sleep(10)\n", getpid_());
    int left = sleep(10);
    if (verbose) fprintf(stderr, "[%d] child slept, %d sec left, had_signal=%d\n",
                         getpid_(), left, had_signal);
    // Expect this sleep to be interrupted by the signal.
    exit(left == 0);
  }

  // Parent: get child's PID.
  pid_t pd_pid;
  EXPECT_OK(pdgetpid(pd, &pd_pid));
  EXPECT_EQ(pid, pd_pid);

  // Kill the child.
  sleep(1);
  EXPECT_OK(pdkill(pd, SIGINT));

  // Make sure the child finished properly.
  CheckChildFinished(pid);
}

FORK_TEST(Pdfork, PdkillSignal) {
  had_signal = 0;
  int pd;
  pid_t pid = pdfork(&pd, 0);
  EXPECT_OK(pid);

  if (pid == 0) {
    // Child: sleep.
    if (verbose) fprintf(stderr, "[%d] child about to sleep(10)\n", getpid_());
    int left = sleep(10);
    if (verbose) fprintf(stderr, "[%d] child slept, %d sec left\n", getpid_(), left);
    exit(99);
  }

  // Kill the child.
  sleep(1);
  EXPECT_OK(pdkill(pd, SIGINT));

  // Make sure the child finished properly.
  CheckChildFinished(pid, true);
}

FORK_TEST(Pdfork, DaemonUnrestricted) {
  EXPECT_OK(cap_enter());
  int fd;

  // Capability mode leaves pdfork() available, with and without flag.
  int rc;
  rc = pdfork(&fd, PD_DAEMON);
  EXPECT_OK(rc);
  if (rc == 0) {
    // Child: immediately terminate.
    exit(0);
  }

  rc = pdfork(&fd, 0);
  EXPECT_OK(rc);
  if (rc == 0) {
    // Child: immediately terminate.
    exit(0);
  }
}

TEST(Pdfork, TimeCheck) {
  time_t now = time(NULL);  // seconds since epoch
  EXPECT_NE(-1, now);
  if (verbose) fprintf(stderr, "Calling pdfork around %ld\n", now);

  int pd = -1;
  pid_t pid = pdfork(&pd, 0);
  EXPECT_OK(pid);
  if (pid == 0) {
    // Child: check we didn't get a valid process descriptor.
    EXPECT_EQ(-1, pdgetpid(pd, &pid));
    EXPECT_EQ(EBADF, errno);
    exit(HasFailure());
  }

  // Parent process. Ensure that [acm]times have been set correctly.
  struct stat stat;
  memset(&stat, 0, sizeof(stat));
  EXPECT_OK(fstat(pd, &stat));
  if (verbose) print_stat(stderr, &stat);


#ifdef HAVE_STAT_BIRTHTIME
  EXPECT_GE(now, stat.st_birthtime);
  EXPECT_EQ(stat.st_birthtime, stat.st_atime);
#endif
  EXPECT_LT((now - stat.st_atime), 2);
  EXPECT_EQ(stat.st_atime, stat.st_ctime);
  EXPECT_EQ(stat.st_ctime, stat.st_mtime);

  // Wait for the child to finish.
  pid_t pd_pid = -1;
  EXPECT_OK(pdgetpid(pd, &pd_pid));
  EXPECT_EQ(pid, pd_pid);
  CheckChildFinished(pid);
}

TEST(Pdfork, UseDescriptor) {
  int pd = -1;
  pid_t pid = pdfork(&pd, 0);
  EXPECT_OK(pid);
  if (pid == 0) {
    // Child: immediately exit
    exit(0);
  }
  // Try read/writing to the process descriptor.
  char buf[] = "bug";
  EXPECT_FAIL_NOT_CAPMODE(write(pd, buf, sizeof(buf)));
  EXPECT_FAIL_NOT_CAPMODE(read(pd, buf, sizeof(buf)));
}

TEST(Pdfork, NonProcessDescriptor) {
  int fd = open("/etc/passwd", O_RDONLY);
  EXPECT_OK(fd);
  // pd*() operations should fail on a non-process descriptor.
  EXPECT_EQ(-1, pdkill(fd, SIGUSR1));
#ifdef HAVE_PDWAIT4
  int status;
  EXPECT_EQ(-1, pdwait4(fd, &status, 0, NULL));
#endif
  pid_t pid;
  EXPECT_EQ(-1, pdgetpid(fd, &pid));
  close(fd);
}

FORK_TEST(Pdfork, MissingRights) {
  pid_t parent = getpid_();
  int pd = -1;
  pid_t pid = pdfork(&pd, 0);
  EXPECT_OK(pid);
  if (pid == 0) {
    // Child: loop forever.
    EXPECT_NE(parent, getpid_());
    while (true) sleep(1);
  }
  // Create two capabilities from the process descriptor.
  cap_rights_t r_rw;
  cap_rights_init(&r_rw, CAP_READ, CAP_WRITE);
  int cap_incapable = dup(pd);
  EXPECT_OK(cap_incapable);
  EXPECT_OK(cap_rights_limit(cap_incapable, &r_rw));
  cap_rights_t r_pdall;
  cap_rights_init(&r_pdall, CAP_PDGETPID, CAP_PDWAIT, CAP_PDKILL);
  int cap_capable = dup(pd);
  EXPECT_OK(cap_capable);
  EXPECT_OK(cap_rights_limit(cap_capable, &r_pdall));

  EXPECT_OK(cap_enter());  // Enter capability mode.
  pid_t other_pid;
  EXPECT_NOTCAPABLE(pdgetpid(cap_incapable, &other_pid));
  EXPECT_NOTCAPABLE(pdkill(cap_incapable, SIGINT));
#ifdef HAVE_PDWAIT4
  int status;
  EXPECT_NOTCAPABLE(pdwait4(cap_incapable, &status, 0, NULL));
#endif

  EXPECT_OK(pdgetpid(cap_capable, &other_pid));
  EXPECT_EQ(pid, other_pid);
  EXPECT_OK(pdkill(cap_capable, SIGINT));
#ifdef HAVE_PDWAIT4
  int rc = pdwait4(pd, &status, 0, NULL);
  EXPECT_OK(rc);
  EXPECT_EQ(pid, rc);
#endif
}
