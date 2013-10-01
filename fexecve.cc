/*
 * Part of a Linux implementation of Capsicum, a capability API for UNIX.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <sstream>

#include "capsicum.h"
#include "capsicum-test.h"

// Arguments to use in execve() calls.
static char* argv_pass[] = {NULL, (char*)"--pass", NULL};
static char* argv_fail[] = {NULL, (char*)"--fail", NULL};
static char* null_envp[] = {NULL};

class Execve : public ::testing::Test {
 public:
  Execve() : self_fd_(open(g_argv_0, O_RDONLY)) {
    argv_pass[0] = (char*)g_argv_0;
    argv_fail[0] = (char*)g_argv_0;
  }
  ~Execve() { if (self_fd_ >= 0) close(self_fd_); }
protected:
  int self_fd_;
};

FORK_TEST_F(Execve, BasicFexecve) {
  EXPECT_OK(sys_fexecve(self_fd_, argv_pass, null_envp));
  // Should not reach here, exec() takes over.
  EXPECT_TRUE(!"fexecve() should never return");
}

FORK_TEST_F(Execve, FailInCapMode) {
  EXPECT_OK(cap_enter());
  EXPECT_EQ(-1, sys_fexecve(self_fd_, argv_pass, null_envp));
  EXPECT_EQ(ECAPMODE, errno);
}

FORK_TEST_F(Execve, FailWithoutCap) {
  EXPECT_OK(cap_enter());
  int cap_fd = cap_new(self_fd_, 0);
  EXPECT_NE(-1, cap_fd);
  EXPECT_EQ(-1, sys_fexecve(cap_fd, argv_fail, null_envp));
  EXPECT_EQ(ENOTCAPABLE, errno);
}

FORK_TEST_F(Execve, SucceedWithCap) {
  EXPECT_OK(cap_enter());
  int cap_fd = cap_new(self_fd_, CAP_FEXECVE);
  EXPECT_NE(-1, cap_fd);
  fprintf(stderr, "cap_fd=%d, argv={%s, %s}\n", cap_fd, argv_pass[0], argv_pass[1]);
  EXPECT_OK(sys_fexecve(cap_fd, argv_pass, null_envp));
  // Should not reach here, exec() takes over.
  EXPECT_TRUE(!"fexecve() should have succeeded");
}

FORK_TEST(Fexecve, ExecutePermissionCheck) {
  // Copy the executable for this program...
  char* copy_filename = tempnam(NULL, NULL);
  std::stringstream ss;
  // ... and remove execute permission
  ss << "cp " << g_argv_0 << " " << copy_filename << " && "
     << "chmod -x " << copy_filename;
  EXPECT_OK(system(ss.str().c_str()));

  int fd = open(copy_filename, O_RDONLY);
  EXPECT_OK(fd);

  EXPECT_EQ(-1, sys_fexecve(fd, argv_fail, null_envp));
  EXPECT_EQ(EACCES, errno);
  if (fd >= 0) close(fd);
  unlink(copy_filename);
  free(copy_filename);
}

FORK_TEST(Fexecve, ExecveFailure) {
  EXPECT_OK(cap_enter());
  EXPECT_EQ(-1, execve(argv_fail[0], argv_fail, null_envp));
  EXPECT_EQ(ECAPMODE, errno);
}
