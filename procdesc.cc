/*
 * Tests for the process descriptor API for Linux.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>

#include <iomanip>

#include "capsicum.h"
#include "syscalls.h"
#include "capsicum-test.h"

TEST(Pdfork, Simple) {
  int pd = -1;
  pid_t parent = getpid_();
  int rc = pdfork(&pd, 0);
  EXPECT_OK(rc);
  if (rc == 0) {
    /* We're the child. */
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
  EXPECT_EQ(rc, pid_got);
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
    int rc = pdfork(&pd_, 0);
    EXPECT_OK(rc);
    if (rc == 0) {
      // Child process: blocking-read an int from the pipe then exit with that value.
      EXPECT_NE(parent, getpid_());
      EXPECT_EQ(parent, getppid());
      read(pipes[0], &rc, sizeof(rc));
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

#ifndef __linux__
  // TODO(drysdale): capsicum-linux currently doesn't generate POLLHUP?
  // Poll again, should have activity on the process descriptor.
  EXPECT_EQ(1, poll(&fdp, 1, 2000));
  EXPECT_TRUE(fdp.revents & POLLHUP);
#endif
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
#ifndef __linux__
  // TODO(drysdale): capsicum-linux currently doesn't generate POLLHUP?
  EXPECT_EQ(1, poll(&fdp, 1, 2000));
  EXPECT_TRUE(fdp.revents & POLLHUP);
#endif

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

// Get the state of a process as a single character.
// On error, return either '?' or '\0'.
static char process_state(int pid) {
#ifdef __linux__
  // Open the process status file.
  char s[1024];
  snprintf(s, sizeof(s), "/proc/%d/status", pid);
  FILE *f = fopen(s, "r");
  if (f == NULL) return '\0';

  // Read the file line by line looking for the state line.
  const char *prompt = "State:\t";
  while (!feof(f)) {
    fgets(s, sizeof(s), f);
    if (!strncmp(s, prompt, strlen(prompt))) {
      fclose(f);
      return s[strlen(prompt)];
    }
  }
  fclose(f);
  return '?';
#endif
#ifdef __FreeBSD__
  char buffer[1024];
  snprintf(buffer, sizeof(buffer), "ps -p %d -o state | grep -v STAT", pid);
  FILE* cmd = popen(buffer, "r");
  int result = fgetc(cmd);
  fclose(cmd);
  // Map FreeBSD codes to Linux codes.
  switch (result) {
    case EOF:
      return '\0';
    case 'D': // disk wait
    case 'R': // runnable
    case 'S': // sleeping
    case 'T': // stopped
    case 'Z': // zombie
      return result;
    case 'W': // idle interrupt thread
      return 'S';
    case 'I': // idle
      return 'S';
    case 'L': // waiting to acquire lock
    default:
      return '?';
  }
#endif
}

// Check process state reaches a particular expected state (or two).
// Retries a few times to allow for timing issues.
#define EXPECT_PID_REACHES_STATES(pid, expected1, expected2) { \
  int counter = 5; \
  char state; \
  do { \
    state = process_state(pid); \
    if (state == expected1 || state == expected2) break; \
    usleep(100000); \
  } while (--counter > 0); \
  EXPECT_TRUE(state == expected1 || state == expected2) \
      << " pid " << pid << " in state " << state; \
}

#define EXPECT_PID_ALIVE(pid) EXPECT_PID_REACHES_STATES(pid, 'R', 'S')
#define EXPECT_PID_DEAD(pid)  EXPECT_PID_REACHES_STATES(pid, 'Z', '\0')

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

TEST_F(PipePdfork, Close) {
  EXPECT_PID_ALIVE(pid_);
  EXPECT_OK(close(pd_));
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
  int status;
#ifdef HAVE_PDWAIT4
  int rc = pdwait4(pd, &status, 0, NULL);
#else
  int rc = waitpid(pid, &status, 0);
#endif
  EXPECT_OK(rc);
  EXPECT_EQ(pid, rc);
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
  EXPECT_OK(kill(pid, SIGKILL));
  EXPECT_PID_DEAD(pid);
}

TEST_F(PipePdfork, Pdkill) {
  EXPECT_PID_ALIVE(pid_);
  // SIGCONT is ignored by default.
  pdkill(pd_, SIGCONT);
  EXPECT_PID_ALIVE(pid_);
  // SIGINT isn't
  pdkill(pd_, SIGINT);
  EXPECT_PID_DEAD(pid_);
}

static int had_signal = 0;
static void handle_signal(int x) { had_signal = 1; }

// The exit of a pdfork()ed process should not generate SIGCHLD.
TEST_F(PipePdfork, NoSigchld) {
  had_signal = 0;
  sighandler_t original = signal(SIGCHLD, handle_signal);
  TerminateChild();
  int rc = 0;
  waitpid(pid_, &rc, 0);
#if PDFORKED_CHILD_SENDS_SIGCHLD
  EXPECT_EQ(1, had_signal);
#else
  EXPECT_TRUE(WIFEXITED(rc)) << "0x" << std::hex << rc;
  EXPECT_EQ(0, had_signal);
#endif
  signal(SIGCHLD, original);
}

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
      EXPECT_TRUE(WIFEXITED(status));
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
    signal(SIGINT, handle_signal);
    int left = sleep(10);
    // Expect this sleep to be interruped by the signal.
    exit(left == 0);
  }

  // Parent: get child's PID.
  pid_t pd_pid;
  EXPECT_OK(pdgetpid(pd, &pd_pid));
  EXPECT_EQ(pid, pd_pid);

  // Kill the child.
  usleep(100);
  EXPECT_OK(pdkill(pd, SIGINT));

  // Make sure the child finished properly.
  CheckChildFinished(pid);
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
  EXPECT_OK(fstat(pd, &stat));

  time_t now = time(NULL);
  EXPECT_NE(-1, now);

#ifdef HAVE_STAT_BIRTHTIME
  EXPECT_GE(now, stat.st_birthtime);
  EXPECT_LT((now - stat.st_birthtime), 2);
  EXPECT_EQ(stat.st_birthtime, stat.st_atime);
#endif
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
  int cap_incapable = cap_new(pd, CAP_READ|CAP_WRITE);
  EXPECT_OK(cap_incapable);
  int cap_capable = cap_new(pd, CAP_PDGETPID|CAP_PDWAIT|CAP_PDKILL);
  EXPECT_OK(cap_capable);

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
