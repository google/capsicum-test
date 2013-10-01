/* -*- C++ -*- */
#ifndef CAPSICUM_TEST_H
#define CAPSICUM_TEST_H

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
        int status;                                            \
        waitpid(pid, &status, 0);                              \
        int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1; \
        EXPECT_EQ(0, rc);                                      \
      }                                                        \
    }                                                          \
    static int test_case_name##_##test_name##_ForkTest()


#endif  // CAPSICUM_TEST_H
