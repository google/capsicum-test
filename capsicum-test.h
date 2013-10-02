/* -*- C++ -*- */
#ifndef CAPSICUM_TEST_H
#define CAPSICUM_TEST_H

#include <errno.h>
#include "gtest/gtest.h"

// Run a test case in a forked process, so that trapdoors don't
// affect other tests.
#define FORK_TEST(test_case_name, test_name)                   \
    static int test_case_name##_##test_name##_ForkTest();      \
    TEST(test_case_name, test_name ## Forked) {                \
      pid_t pid = fork();                                      \
      if (pid == 0) {                                          \
        test_case_name##_##test_name##_ForkTest();             \
        exit(HasFailure());                                    \
      } else if (pid > 0) {                                    \
        int status = 0;                                        \
        int remaining_us = 10000000;                           \
        while (remaining_us > 0) {                             \
          if (waitpid(pid, &status, WNOHANG) != 0) break;      \
          remaining_us -= 10000;                               \
          usleep(10000);                                       \
        }                                                      \
        if (remaining_us <= 0) {                               \
          fprintf(stderr, "Warning: killing unresponsive test %s.%s (pid %d)\n", \
                  #test_case_name, #test_name, pid);           \
          kill(pid, SIGKILL);                                  \
          ADD_FAILURE() << "Test hung";                        \
        } else {                                               \
          int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1; \
          EXPECT_EQ(0, rc);                                    \
        }                                                      \
      }                                                        \
    }                                                          \
    static int test_case_name##_##test_name##_ForkTest()

// Run a test case fixture in a forked process, so that trapdoors don't
// affect other tests.
#define ICLASS_NAME(test_case_name, test_name) \
    Forked##test_case_name##_##test_name
#define FORK_TEST_F(test_case_name, test_name)                \
  class ICLASS_NAME(test_case_name, test_name) : public test_case_name { \
    public:                                                    \
      ICLASS_NAME(test_case_name, test_name)() {}              \
    protected:                                                 \
      void InnerTestBody();                                    \
    };                                                         \
    TEST_F(ICLASS_NAME(test_case_name, test_name), _) {        \
      pid_t pid = fork();                                      \
      if (pid == 0) {                                          \
        InnerTestBody();                                       \
        exit(HasFailure());                                    \
      } else if (pid > 0) {                                    \
        int status;                                            \
        waitpid(pid, &status, 0);                              \
        int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1; \
        EXPECT_EQ(0, rc);                                      \
      }                                                        \
    }                                                          \
    void ICLASS_NAME(test_case_name, test_name)::InnerTestBody()

// Emit errno information on failure
#define EXPECT_OK(v) EXPECT_LE(0, v) << "   errno " << errno << " " << strerror(errno);

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

#endif  // CAPSICUM_TEST_H
