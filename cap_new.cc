/*
 * Tests for Capsicum, a capability API for UNIX.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <stdio.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "capsicum.h"

TEST(Capability, CapNew) {
  int cap_fd = cap_new(STDOUT_FILENO, CAP_READ|CAP_WRITE|CAP_SEEK);
  EXPECT_NE(-1, cap_fd);
  EXPECT_EQ(4, write(cap_fd, "OK!\n", 4));
  EXPECT_EQ(0, close(cap_fd));
}

TEST(Capability, CapEnterDeathTest) {
  EXPECT_EQ(0, cap_enter());
}
