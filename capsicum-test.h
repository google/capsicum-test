/* -*- C++ -*- */
#ifndef CAPSICUM_TEST_H
#define CAPSICUM_TEST_H

#include <errno.h>
#include "gtest/gtest.h"

extern const char* g_argv_0;

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
        int status;                                            \
        waitpid(pid, &status, 0);                              \
        int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1; \
        EXPECT_EQ(0, rc);                                      \
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

#endif  // CAPSICUM_TEST_H
