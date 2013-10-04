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
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <sstream>

#include "capsicum.h"
#include "capsicum-test.h"

// We need a program to exec(), but for fexecve() to work in capability
// mode that program needs to be statically linked (otherwise ld.so will
// attempt to traverse the filesystem to load (e.g.) /lib/libc.so and
// fail).
#define EXEC_PROG "./mini-me"
#define EXEC_PROG_NOEXEC  EXEC_PROG ".noexec"

// Arguments to use in execve() calls.
static char* argv_pass[] = {(char*)EXEC_PROG, (char*)"--pass", NULL};
static char* argv_fail[] = {(char*)EXEC_PROG, (char*)"--fail", NULL};
static char* null_envp[] = {NULL};

class Execve : public ::testing::Test {
 public:
  Execve() : exec_fd_(open(EXEC_PROG, O_RDONLY)) {
    if (exec_fd_ < 0) {
      fprintf(stderr, "Error! Failed to open %s\n", EXEC_PROG);
    }
  }
  ~Execve() { if (exec_fd_ >= 0) close(exec_fd_); }
protected:
  int exec_fd_;
};

FORK_TEST_F(Execve, BasicFexecve) {
  EXPECT_OK(fexecve_(exec_fd_, argv_pass, null_envp));
  // Should not reach here, exec() takes over.
  EXPECT_TRUE(!"fexecve() should never return");
}

FORK_TEST_F(Execve, FailInCapMode) {
  EXPECT_OK(cap_enter());
  EXPECT_EQ(-1, fexecve_(exec_fd_, argv_pass, null_envp));
  EXPECT_EQ(ECAPMODE, errno);
}

FORK_TEST_F(Execve, FailWithoutCap) {
  EXPECT_OK(cap_enter());
  int cap_fd = cap_new(exec_fd_, 0);
  EXPECT_NE(-1, cap_fd);
  EXPECT_EQ(-1, fexecve_(cap_fd, argv_fail, null_envp));
  EXPECT_EQ(ENOTCAPABLE, errno);
}

FORK_TEST_F(Execve, SucceedWithCap) {
  EXPECT_OK(cap_enter());
  int cap_fd = cap_new(exec_fd_, CAP_FEXECVE);
  EXPECT_NE(-1, cap_fd);
  EXPECT_OK(fexecve_(cap_fd, argv_pass, null_envp));
  // Should not reach here, exec() takes over.
  EXPECT_TRUE(!"fexecve() should have succeeded");
}

FORK_TEST(Fexecve, ExecutePermissionCheck) {
  int fd = open(EXEC_PROG_NOEXEC, O_RDONLY);
  EXPECT_OK(fd);
  if (fd >= 0) {
    struct stat data;
    EXPECT_OK(fstat(fd, &data));
    EXPECT_EQ(0, data.st_mode & (S_IXUSR|S_IXGRP|S_IXOTH));
    EXPECT_EQ(-1, fexecve_(fd, argv_fail, null_envp));
    EXPECT_EQ(EACCES, errno);
    close(fd);
  }
}

FORK_TEST(Fexecve, ExecveFailure) {
  EXPECT_OK(cap_enter());
  EXPECT_EQ(-1, execve(argv_fail[0], argv_fail, null_envp));
  EXPECT_EQ(ECAPMODE, errno);
}
