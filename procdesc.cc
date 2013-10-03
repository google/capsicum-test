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
#include "capsicum-test.h"

TEST(Pdfork, Simple) {
  int pd = -1;
  int rc = pdfork(&pd, 0);
  EXPECT_OK(rc);
  if (rc == 0) {
    /* We're the child. */
    EXPECT_EQ(-1, pd);
    exit(0);
  }
  EXPECT_NE(-1, pd);
  int pid_got;
  EXPECT_OK(pdgetpid(pd, &pid_got));
  EXPECT_EQ(rc, pid_got);
  EXPECT_OK(close(pd));
}

class PipePdfork : public ::testing::Test {
 public:
  PipePdfork() : pd_(-1), pid_(-1) {
    int pipes[2];
    EXPECT_OK(pipe(pipes));
    pipe_ = pipes[1];
    int rc = pdfork(&pd_, 0);
    EXPECT_OK(rc);
    if (rc == 0) {
      // Child process: blocking-read an int from the pipe then exit with that value.
      read(pipes[0], &rc, sizeof(rc));
      exit(rc);
    } else {
      pid_ = rc;
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
 protected:
  int pd_;
  int pipe_;
  int pid_;
};


// Can we poll a process descriptor?
TEST_F(PipePdfork, Poll) {
  // Poll the process descriptor, nothing happening.
  struct pollfd fdp;
  fdp.fd = pd_;
  fdp.events = POLLIN | POLLERR | POLLHUP;
  fdp.revents = 0;
  EXPECT_EQ(0, poll(&fdp, 1, 0));

  // Tell the child to exit.
  int zero = 0;
  write(pipe_, &zero, sizeof(zero));

  // Poll again, should have activity on the process descriptor.
  EXPECT_EQ(1, poll(&fdp, 1, 2000));
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
    int zero = 0;
    write(pipe_, &zero, sizeof(zero));
    exit(0);
  }

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
static void ExpectPidReachesStates(pid_t pid, int expected1, int expected2) {
  int counter = 5;
  char state;
  do {
    state = process_state(pid);
    if (state == expected1 || state == expected2) return;
    usleep(100000);
  } while (--counter > 0);
  EXPECT_TRUE(state == expected1 || state == expected2);
}

static void ExpectPidReachesState(pid_t pid, int expected) {
  int counter = 5;
  char state;
  do {
    state = process_state(pid);
    if (state == expected) return;
    usleep(100000);
  } while (--counter > 0);
  EXPECT_EQ(expected, state);
}
#define EXPECT_PID_ALIVE(pid) ExpectPidReachesStates(pid, 'R', 'S')
#define EXPECT_PID_DEAD(pid)  ExpectPidReachesStates(pid, 'Z', '\0')

// Check whether a pdfork()ed process dies correctly when released.
// Can only check zombification.
// TODO(drysdale): revisit when pdwait4() implemented
TEST_F(PipePdfork, Release) {
  EXPECT_PID_ALIVE(pid_);
  int zero = 0;
  EXPECT_EQ(sizeof(zero), write(pipe_, &zero, sizeof(zero)));
  EXPECT_PID_DEAD(pid_);
  pid_ = 0;
}

TEST_F(PipePdfork, Close) {
  EXPECT_PID_ALIVE(pid_);
  EXPECT_OK(close(pd_));
  EXPECT_PID_DEAD(pid_);
}

// Setting PD_DAEMON prevents close() from killing the child.
TEST(Pdfork, CloseDaemon) {
  int pd = -1;
  int pid = pdfork(&pd, PD_DAEMON);
  EXPECT_OK(pid);
  if (pid == 0) {
    // Child: loop forever.
    while (1) sleep(1);
  }
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
  sighandler_t original = signal(SIGCHLD, handle_signal);
  int zero = 0;
  write(pipe_, &zero, sizeof(zero));
  int rc = 0;
  waitpid(pid_, &rc, 0);
  EXPECT_TRUE(WIFEXITED(rc)) << "0x" << std::hex << rc;
  EXPECT_EQ(0, had_signal);
  signal(SIGCHLD, original);
}

FORK_TEST(Pdfork, DaemonRestricted) {
  EXPECT_OK(cap_enter());
  int fd;
  EXPECT_EQ(-1, pdfork(&fd, PD_DAEMON));
  EXPECT_EQ(ECAPMODE, errno);

  int rc = pdfork(&fd, 0);
  EXPECT_OK(rc);
  if (rc == 0) {
    // Child: immediately terminate.
    exit(0);
  }
}
