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
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/time.h>
/* Different includes for fstatfs(2) */
#ifdef __FreeBSD__
#include <sys/param.h>
#include <sys/mount.h>
#else
#include <sys/statfs.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#include "capsicum.h"
#include "syscalls.h"
#include "capsicum-test.h"

FORK_TEST(Capability, CapNew) {
  int cap_fd = cap_new(STDOUT_FILENO, CAP_READ|CAP_WRITE|CAP_SEEK);
  EXPECT_OK(cap_fd);
  if (cap_fd < 0) return;
  int rc = write(cap_fd, "OK!\n", 4);
  EXPECT_OK(rc);
  EXPECT_EQ(4, rc);
  cap_rights_t rights;
  EXPECT_OK(cap_getrights(cap_fd, &rights));
  EXPECT_EQ(CAP_READ|CAP_WRITE|CAP_SEEK, rights);

  // Try to get a disjoint set of rights in a sub-capability.
  int cap_cap_fd = cap_new(cap_fd, CAP_READ|CAP_SEEK|CAP_MMAP|CAP_FCHMOD);
  if (cap_cap_fd < 0) {
    // Either we fail with ENOTCAPABLE
    EXPECT_EQ(ENOTCAPABLE, errno);
  } else {
    // Or we succeed and the rights are subsetted anyway.
    EXPECT_OK(cap_getrights(cap_cap_fd, &rights));
    EXPECT_EQ(CAP_READ|CAP_SEEK, rights);
    // Check in practice as well as in theory.
    EXPECT_OK(cap_enter());
    int rc = fchmod(cap_cap_fd, 0644);
    EXPECT_EQ(-1, rc);
    EXPECT_EQ(ENOTCAPABLE, errno);
    EXPECT_OK(close(cap_cap_fd));
  }
  EXPECT_OK(close(cap_fd));
}

FORK_TEST(Capability, CapEnter) {
  EXPECT_EQ(0, cap_enter());
}

FORK_TEST(Capability, BasicInterception) {
  int cap_fd = cap_new(1, 0);
  EXPECT_NE(-1, cap_fd);

  int rc;
#ifdef HAVE_RIGHTS_CHECK_OUTSIDE_CAPMODE
  rc = write(cap_fd, "", 0);
  EXPECT_EQ(-1, rc);
  EXPECT_EQ(ENOTCAPABLE, errno);
#endif

  EXPECT_OK(cap_enter());

  rc = write(cap_fd, "", 0);
  EXPECT_EQ(-1, rc);
  EXPECT_EQ(ENOTCAPABLE, errno);

  // Create a new capability which does have write permission
  int cap_fd2 = cap_new(1, CAP_WRITE|CAP_SEEK);
  EXPECT_OK(cap_fd2);
  rc = write(cap_fd2, "", 0);
  EXPECT_OK(rc);

  // Tidy up.
  if (cap_fd >= 0) close(cap_fd);
  if (cap_fd2 >= 0) close(cap_fd2);
}

FORK_TEST_ON(Capability, OpenAtDirectoryTraversal, "/tmp/cap_openat_testfile") {
  int dir = open("/tmp", O_RDONLY);
  EXPECT_OK(dir);

  cap_enter();

  int file = openat(dir, "cap_openat_testfile", O_RDONLY|O_CREAT, 0644);
  EXPECT_OK(file);

  // Test that we are confined to /tmp, and cannot
  // escape using absolute paths or ../.
  int new_file = openat(dir, "../dev/null", O_RDONLY);
  EXPECT_EQ(-1, new_file);

  new_file = openat(dir, "..", O_RDONLY);
  EXPECT_EQ(-1, new_file);

  new_file = openat(dir, "/dev/null", O_RDONLY);
  EXPECT_EQ(-1, new_file);

  new_file = openat(dir, "/", O_RDONLY);
  EXPECT_EQ(-1, new_file);

  // Tidy up.
  close(file);
  close(dir);
}

// Create a capability on /tmp that does not allow CAP_WRITE,
// and check that this restriction is inherited through openat().
FORK_TEST_ON(Capability, Inheritance, "/tmp/cap_openat_write_testfile") {
  int dir = open("/tmp", O_RDONLY);
  EXPECT_OK(dir);
  int cap_dir = cap_new(dir, CAP_READ|CAP_LOOKUP);

  const char *filename = "cap_openat_write_testfile";
  int file = openat(dir, filename, O_WRONLY|O_CREAT, 0644);
  EXPECT_OK(file);
  EXPECT_EQ(5, write(file, "TEST\n", 5));
  if (file >= 0) close(file);

  EXPECT_OK(cap_enter());
  file = openat(cap_dir, filename, O_RDONLY);
  EXPECT_OK(file);
  if (file >= 0) close(file);

  file = openat(cap_dir, filename, O_WRONLY|O_APPEND);
  EXPECT_EQ(-1, file);
  EXPECT_EQ(ENOTCAPABLE, errno);
  if (file > 0) close(file);

  if (dir > 0) close(dir);
  if (cap_dir > 0) close(cap_dir);
}


// Ensure that, if the capability had enough rights for the system call to
// pass, then it did. Otherwise, ensure that the errno is ENOTCAPABLE;
// capability restrictions should kick in before any other error logic.
#define CHECK_RIGHT_RESULT(result, rights, rights_needed) do { \
  if (((rights) & (rights_needed)) == (rights_needed)) {       \
    EXPECT_OK(result);                                         \
  } else {                                                     \
    EXPECT_EQ(-1, result);                                     \
    EXPECT_EQ(ENOTCAPABLE, errno);                             \
  }                                                            \
} while (0)

// As above, but for the special mmap() case: unmap after successful mmap().
#define CHECK_RIGHT_MMAP_RESULT(result, rights, rights_needed) do { \
  if (((rights) & (rights_needed)) == (rights_needed)) {            \
    EXPECT_NE(MAP_FAILED, result);                                  \
  } else {                                                          \
    EXPECT_EQ(MAP_FAILED, result);                                  \
    EXPECT_EQ(ENOTCAPABLE, errno);                                  \
  }                                                                 \
  if (result != MAP_FAILED) munmap(result, getpagesize());          \
} while(0)

// Given a file descriptor, create a capability with specific rights and
// make sure only those rights work.
static void TryFileOps(int fd, cap_rights_t rights) {
  int cap_fd = cap_new(fd, rights);
  EXPECT_OK(cap_fd);
  if (cap_fd < 0) return;

  // Check creation of a capability form a capability.
  int cap_cap_fd = cap_new(cap_fd, rights);
  EXPECT_OK(cap_cap_fd);
  EXPECT_NE(cap_fd, cap_cap_fd);
  close(cap_cap_fd);

  char ch;
  CHECK_RIGHT_RESULT(read(cap_fd, &ch, sizeof(ch)), rights, CAP_READ|CAP_SEEK);

  ssize_t len1 = pread(cap_fd, &ch, sizeof(ch), 0);
  CHECK_RIGHT_RESULT(len1, rights, CAP_READ);
  ssize_t len2 = pread(cap_fd, &ch, sizeof(ch), 0);
  CHECK_RIGHT_RESULT(len2, rights, CAP_READ);
  EXPECT_EQ(len1, len2);

  CHECK_RIGHT_RESULT(write(cap_fd, &ch, sizeof(ch)), rights, CAP_WRITE|CAP_SEEK);
  CHECK_RIGHT_RESULT(pwrite(cap_fd, &ch, sizeof(ch), 0), rights, CAP_WRITE);
  CHECK_RIGHT_RESULT(lseek(cap_fd, 0, SEEK_SET), rights, CAP_SEEK);

#ifdef HAVE_CHFLAGS
  // Note: this is not expected to work over NFS.
  struct statfs sf;
  EXPECT_OK(fstatfs(fd, &sf));
  bool is_nfs = (strncmp("nfs", sf.f_fstypename, sizeof(sf.f_fstypename)) == 0);
  if (!is_nfs) {
    CHECK_RIGHT_RESULT(fchflags(cap_fd, UF_NODUMP), rights, CAP_FCHFLAGS);
  }
#endif

  struct stat sb;
  CHECK_RIGHT_RESULT(fstat(cap_fd, &sb), rights, CAP_FSTAT);

  CHECK_RIGHT_MMAP_RESULT(mmap(NULL, getpagesize(), PROT_READ, MAP_SHARED, cap_fd, 0),
                          rights, CAP_MMAP | CAP_READ);
  CHECK_RIGHT_MMAP_RESULT(mmap(NULL, getpagesize(), PROT_WRITE, MAP_SHARED, cap_fd, 0),
                          rights, CAP_MMAP | CAP_WRITE);
  CHECK_RIGHT_MMAP_RESULT(mmap(NULL, getpagesize(), PROT_EXEC, MAP_SHARED, cap_fd, 0),
                          rights, (CAP_MMAP | CAP_MAPEXEC));
  CHECK_RIGHT_MMAP_RESULT(mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, cap_fd, 0),
                          rights, (CAP_MMAP | CAP_READ | CAP_WRITE));
  CHECK_RIGHT_MMAP_RESULT(mmap(NULL, getpagesize(), PROT_READ | PROT_EXEC, MAP_SHARED, cap_fd, 0),
                          rights, (CAP_MMAP | CAP_READ | CAP_MAPEXEC));
  CHECK_RIGHT_MMAP_RESULT(mmap(NULL, getpagesize(), PROT_EXEC | PROT_WRITE, MAP_SHARED, cap_fd, 0),
                          rights, (CAP_MMAP | CAP_MAPEXEC | CAP_WRITE));
  CHECK_RIGHT_MMAP_RESULT(mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, cap_fd, 0),
                          rights, (CAP_MMAP | CAP_READ | CAP_WRITE | CAP_MAPEXEC));

  CHECK_RIGHT_RESULT(fsync(cap_fd), rights, CAP_FSYNC);

  CHECK_RIGHT_RESULT(fchown(cap_fd, -1, -1), rights, CAP_FCHOWN);

  CHECK_RIGHT_RESULT(fchmod(cap_fd, 0644), rights, CAP_FCHMOD);

  CHECK_RIGHT_RESULT(flock(cap_fd, LOCK_SH), rights, CAP_FLOCK);
  CHECK_RIGHT_RESULT(flock(cap_fd, LOCK_UN), rights, CAP_FLOCK);

  CHECK_RIGHT_RESULT(ftruncate(cap_fd, 0), rights, CAP_FTRUNCATE);

  struct statfs cap_sf;
  CHECK_RIGHT_RESULT(fstatfs(cap_fd, &cap_sf), rights, CAP_FSTATFS);

#ifdef HAVE_FPATHCONF
  CHECK_RIGHT_RESULT(fpathconf(cap_fd, _PC_NAME_MAX), rights, CAP_FPATHCONF);
#endif

  CHECK_RIGHT_RESULT(futimes(cap_fd, NULL), rights, CAP_FUTIMES);

  struct pollfd pollfd;
  pollfd.fd = cap_fd;
  pollfd.events = POLLIN | POLLERR | POLLHUP;
  pollfd.revents = 0;
  int ret = poll(&pollfd, 1, 0);
  if (rights & CAP_POLL_EVENT) {
    EXPECT_OK(ret);
  } else {
    if (POLLNVAL_FOR_INVALID_POLLFD) {
      EXPECT_NE(0, (pollfd.revents & POLLNVAL));
    } else {
      EXPECT_NOTCAPABLE(ret);
    }
  }

  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 100;
  fd_set rset;
  FD_ZERO(&rset);
  FD_SET(cap_fd, &rset);
  fd_set wset;
  FD_ZERO(&wset);
  FD_SET(cap_fd, &wset);
  ret = select(cap_fd+1, &rset, &wset, NULL, &tv);
  if (rights & CAP_POLL_EVENT) {
    EXPECT_OK(ret);
  } else {
    EXPECT_NOTCAPABLE(ret);
  }

  // TODO(drysdale): kqueue (FreeBSD only)

  EXPECT_OK(close(cap_fd));
}

FORK_TEST_ON(Capability, Operations, "/tmp/cap_fd_operations") {
  int fd = open("/tmp/cap_fd_operations", O_RDWR | O_CREAT, 0644);
  EXPECT_OK(fd);
  if (fd < 0) return;

  EXPECT_OK(cap_enter());

  // Try a variety of different combinations of rights - a full
  // enumeration is too large (2^N with N~30+) to perform.
  TryFileOps(fd, CAP_READ);
  TryFileOps(fd, CAP_READ | CAP_SEEK);
  TryFileOps(fd, CAP_WRITE);
  TryFileOps(fd, CAP_WRITE | CAP_SEEK);
  TryFileOps(fd, CAP_READ | CAP_WRITE);
  TryFileOps(fd, CAP_READ | CAP_WRITE | CAP_SEEK);
  TryFileOps(fd, CAP_SEEK);
  TryFileOps(fd, CAP_FCHFLAGS);
  TryFileOps(fd, CAP_IOCTL);
  TryFileOps(fd, CAP_FSTAT);
  TryFileOps(fd, CAP_MMAP);
  TryFileOps(fd, CAP_MMAP | CAP_READ);
  TryFileOps(fd, CAP_MMAP | CAP_WRITE);
  TryFileOps(fd, CAP_MMAP | CAP_MAPEXEC);
  TryFileOps(fd, CAP_MMAP | CAP_READ | CAP_WRITE);
  TryFileOps(fd, CAP_MMAP | CAP_READ | CAP_MAPEXEC);
  TryFileOps(fd, CAP_MMAP | CAP_MAPEXEC | CAP_WRITE);
  TryFileOps(fd, CAP_MMAP | CAP_READ | CAP_WRITE | CAP_MAPEXEC);
  TryFileOps(fd, CAP_FCNTL);
  TryFileOps(fd, CAP_POST_EVENT);
  TryFileOps(fd, CAP_POLL_EVENT);
  TryFileOps(fd, CAP_FSYNC);
  TryFileOps(fd, CAP_FCHOWN);
  TryFileOps(fd, CAP_FCHMOD);
  TryFileOps(fd, CAP_FTRUNCATE);
  TryFileOps(fd, CAP_FLOCK);
  TryFileOps(fd, CAP_FSTATFS);
  TryFileOps(fd, CAP_FPATHCONF);
  TryFileOps(fd, CAP_FUTIMES);
  TryFileOps(fd, CAP_ACL_GET);
  TryFileOps(fd, CAP_ACL_SET);
  TryFileOps(fd, CAP_ACL_DELETE);
  TryFileOps(fd, CAP_ACL_CHECK);
  TryFileOps(fd, CAP_EXTATTR_GET);
  TryFileOps(fd, CAP_EXTATTR_SET);
  TryFileOps(fd, CAP_EXTATTR_DELETE);
  TryFileOps(fd, CAP_EXTATTR_LIST);
  TryFileOps(fd, CAP_MAC_GET);
  TryFileOps(fd, CAP_MAC_SET);

  // Socket-specific.
  TryFileOps(fd, CAP_GETPEERNAME);
  TryFileOps(fd, CAP_GETSOCKNAME);
  TryFileOps(fd, CAP_ACCEPT);

  close(fd);
}
