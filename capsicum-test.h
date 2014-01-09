/* -*- C++ -*- */
#ifndef CAPSICUM_TEST_H
#define CAPSICUM_TEST_H

#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#include <ios>

#include "gtest/gtest.h"

// Run the given test function in a forked process, so that trapdoor
// entry doesn't affect other tests, and watch out for hung processes.
// Implemented as a macro to allow access to the test case instance's
// HasFailure() method, which is reported as the forked process's
// exit status.
#define _RUN_FORKED(TESTFN, TESTCASENAME, TESTNAME)            \
    pid_t pid = fork();                                        \
    if (pid == 0) {                                            \
      TESTFN();                                                \
      exit(HasFailure());                                      \
    } else if (pid > 0) {                                      \
      int rc, status;                                          \
      int remaining_us = 10000000;                             \
      while (remaining_us > 0) {                               \
        status = 0;                                            \
        rc = waitpid(pid, &status, WNOHANG);                   \
        if (rc != 0) break;                                    \
        remaining_us -= 10000;                                 \
        usleep(10000);                                         \
      }                                                        \
      if (remaining_us <= 0) {                                 \
        fprintf(stderr, "Warning: killing unresponsive test "  \
                        "%s.%s (pid %d)\n",                    \
                        TESTCASENAME, TESTNAME, pid);          \
        kill(pid, SIGKILL);                                    \
        ADD_FAILURE() << "Test hung";                          \
      } else if (rc < 0) {                                     \
        fprintf(stderr, "Warning: waitpid error %s (%d)\n",    \
                        strerror(errno), errno);               \
        ADD_FAILURE() << "Failed to wait for child";           \
      } else {                                                 \
        int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1; \
        EXPECT_EQ(0, rc);                                      \
      }                                                        \
    }

// Run a test case in a forked process, possibly cleaning up a
// test file after completion
#define FORK_TEST_ON(test_case_name, test_name, test_file)     \
    static void test_case_name##_##test_name##_ForkTest();     \
    TEST(test_case_name, test_name ## Forked) {                \
      _RUN_FORKED(test_case_name##_##test_name##_ForkTest,     \
                  #test_case_name, #test_name);                \
      const char *filename = test_file;                        \
      if (filename) unlink(filename);                          \
    }                                                          \
    static void test_case_name##_##test_name##_ForkTest()

#define FORK_TEST(test_case_name, test_name) FORK_TEST_ON(test_case_name, test_name, NULL)

// Run a test case fixture in a forked process, so that trapdoors don't
// affect other tests.
#define ICLASS_NAME(test_case_name, test_name) Forked##test_case_name##_##test_name
#define FORK_TEST_F(test_case_name, test_name)                \
  class ICLASS_NAME(test_case_name, test_name) : public test_case_name { \
    public:                                                    \
      ICLASS_NAME(test_case_name, test_name)() {}              \
    protected:                                                 \
      void InnerTestBody();                                    \
    };                                                         \
    TEST_F(ICLASS_NAME(test_case_name, test_name), _) {        \
      _RUN_FORKED(InnerTestBody, #test_case_name, #test_name); \
    }                                                          \
    void ICLASS_NAME(test_case_name, test_name)::InnerTestBody()

// Emit errno information on failure
#define EXPECT_OK(v) EXPECT_LE(0, v) << "   errno " << errno << " " << strerror(errno)

// Expect a syscall to fail with the given error.
#define EXPECT_SYSCALL_FAIL(E, C) \
    do { \
      EXPECT_GT(0, C); \
      EXPECT_EQ(E, errno); \
    } while (0)

// Expect a syscall to fail with anything other than the given error.
#define EXPECT_SYSCALL_FAIL_NOT(E, C) \
    do { \
      EXPECT_GT(0, C); \
      EXPECT_NE(E, errno); \
    } while (0)

// Expect a void syscall to fail with anything other than the given error.
#define EXPECT_VOID_SYSCALL_FAIL_NOT(E, C)   \
    do { \
      errno = 0; \
      C; \
      EXPECT_NE(E, errno) << #C << " failed with ECAPMODE"; \
    } while (0)

// Expect a system call to fail with ECAPMODE.
#define EXPECT_CAPMODE(C) EXPECT_SYSCALL_FAIL(ECAPMODE, C)

// Expect a system call to fail, but not with ECAPMODE.
#define EXPECT_FAIL_NOT_CAPMODE(C) EXPECT_SYSCALL_FAIL_NOT(ECAPMODE, C)
#define EXPECT_FAIL_VOID_NOT_CAPMODE(C) EXPECT_VOID_SYSCALL_FAIL_NOT(ECAPMODE, C)

// Expect a system call to fail with ENOTCAPABLE.
#define EXPECT_NOTCAPABLE(C) EXPECT_SYSCALL_FAIL(ENOTCAPABLE, C)

// Expect a system call to fail, but not with ENOTCAPABLE.
#define EXPECT_FAIL_NOT_NOTCAPABLE(C) EXPECT_SYSCALL_FAIL_NOT(ENOTCAPABLE, C)

// Expect a system call to fail with either ENOTCAPABLE or ECAPMODE.
#define EXPECT_CAPFAIL(C) \
    do { \
      int rc = C; \
      EXPECT_GT(0, rc); \
      EXPECT_TRUE(errno == ECAPMODE || errno == ENOTCAPABLE) \
        << #C << " did not fail with ECAPMODE/ENOTCAPABLE but " << errno; \
    } while (0)

// Ensure that 'rights' are a subset of 'max'.
#define EXPECT_RIGHTS_IN(rights, max) \
    EXPECT_EQ((rights) & (max), (rights)) \
    << "rights " << std::hex << (rights)        \
    << " not a subset of " << std::hex << (max)

// Mark a test that can only be run as root.
#define REQUIRE_ROOT() \
  if (getuid() != 0) { \
    fprintf(stderr, "This test needs to be run as root; skipping\n"); \
    return; \
  }

// Get the state of a process as a single character.
//  - 'D': disk wait
//  - 'R': runnable
//  - 'S': sleeping
//  - 'T': stopped
//  - 'Z': zombie
//  - 'S': idle
// On error, return either '?' or '\0'.
char ProcessState(int pid);

// Check process state reaches a particular expected state (or two).
// Retries a few times to allow for timing issues.
#define EXPECT_PID_REACHES_STATES(pid, expected1, expected2) { \
  int counter = 5; \
  char state; \
  do { \
    state = ProcessState(pid); \
    if (state == expected1 || state == expected2) break; \
    usleep(100000); \
  } while (--counter > 0); \
  EXPECT_TRUE(state == expected1 || state == expected2) \
      << " pid " << pid << " in state " << state; \
}

#define EXPECT_PID_ALIVE(pid) EXPECT_PID_REACHES_STATES(pid, 'R', 'S')
#define EXPECT_PID_DEAD(pid)  EXPECT_PID_REACHES_STATES(pid, 'Z', '\0')

#endif  // CAPSICUM_TEST_H
