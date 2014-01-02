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
#include <sys/socket.h>
#include <sys/time.h>
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
  rc = write(cap_fd, "", 0);
  EXPECT_EQ(-1, rc);
  EXPECT_EQ(ENOTCAPABLE, errno);

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

FORK_TEST_ON(Capability, FileInSync, "/tmp/cap_file_sync") {
  int fd = open("/tmp/cap_file_sync", O_RDWR|O_CREAT, 0644);
  EXPECT_OK(fd);
  const char* message = "Hello capability world";
  EXPECT_OK(write(fd, message, strlen(message)));

  int cap_fd = cap_new(fd, CAP_READ|CAP_SEEK|CAP_FSTAT);
  EXPECT_OK(cap_fd);
  int cap_cap_fd = cap_new(cap_fd, CAP_READ|CAP_SEEK|CAP_FSTAT);
  EXPECT_OK(cap_cap_fd);

  EXPECT_OK(cap_enter());  // Enter capability mode.

  // Changes to one file descriptor affect the others.
  EXPECT_EQ(1, lseek(fd, 1, SEEK_SET));
  EXPECT_EQ(1, lseek(fd, 0, SEEK_CUR));
  EXPECT_EQ(1, lseek(cap_fd, 0, SEEK_CUR));
  EXPECT_EQ(1, lseek(cap_cap_fd, 0, SEEK_CUR));
  EXPECT_EQ(3, lseek(cap_fd, 3, SEEK_SET));
  EXPECT_EQ(3, lseek(fd, 0, SEEK_CUR));
  EXPECT_EQ(3, lseek(cap_fd, 0, SEEK_CUR));
  EXPECT_EQ(3, lseek(cap_cap_fd, 0, SEEK_CUR));
  EXPECT_EQ(5, lseek(cap_cap_fd, 5, SEEK_SET));
  EXPECT_EQ(5, lseek(fd, 0, SEEK_CUR));
  EXPECT_EQ(5, lseek(cap_fd, 0, SEEK_CUR));
  EXPECT_EQ(5, lseek(cap_cap_fd, 0, SEEK_CUR));

  close(cap_cap_fd);
  close(cap_fd);
  close(fd);
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

#define EXPECT_MMAP_NOTCAPABLE(result) do {         \
  void *rv = result;                                \
  EXPECT_EQ(MAP_FAILED, rv);                        \
  EXPECT_EQ(ENOTCAPABLE, errno);                    \
  if (rv != MAP_FAILED) munmap(rv, getpagesize());  \
} while (0)

#define EXPECT_MMAP_OK(result) do {                     \
  void *rv = result;                                    \
  EXPECT_NE(MAP_FAILED, rv) << " with errno " << errno; \
  if (rv != MAP_FAILED) munmap(rv, getpagesize());      \
} while (0)


// As above, but for the special mmap() case: unmap after successful mmap().
#define CHECK_RIGHT_MMAP_RESULT(result, rights, rights_needed) do { \
  if (((rights) & (rights_needed)) == (rights_needed)) {            \
    EXPECT_MMAP_OK(result);                                         \
  } else {                                                          \
    EXPECT_MMAP_NOTCAPABLE(result);                                 \
  }                                                                 \
} while(0)

FORK_TEST_ON(Capability, Mmap, "/tmp/cap_mmap_operations") {
  int fd = open("/tmp/cap_mmap_operations", O_RDWR | O_CREAT, 0644);
  EXPECT_OK(fd);
  if (fd < 0) return;

  /* If we're missing a capability, it will fail. */
  int cap_none = cap_new(fd, 0);
  EXPECT_OK(cap_none);
  int cap_mmap = cap_new(fd, CAP_MMAP);
  EXPECT_OK(cap_mmap);
  int cap_read = cap_new(fd, CAP_READ);
  EXPECT_OK(cap_read);
  int cap_both = cap_new(fd, CAP_MMAP | CAP_READ);
  EXPECT_OK(cap_both);

  EXPECT_OK(cap_enter());  // Enter capability mode.

  EXPECT_MMAP_NOTCAPABLE(mmap(NULL, getpagesize(), PROT_READ, MAP_PRIVATE, cap_none, 0));
  EXPECT_MMAP_NOTCAPABLE(mmap(NULL, getpagesize(), PROT_READ, MAP_PRIVATE, cap_mmap, 0));
  EXPECT_MMAP_NOTCAPABLE(mmap(NULL, getpagesize(), PROT_READ, MAP_PRIVATE, cap_read, 0));

  EXPECT_MMAP_OK(mmap(NULL, getpagesize(), PROT_READ, MAP_PRIVATE, cap_both, 0));

  // A call with MAP_ANONYMOUS should succeed without any capability requirements.
  EXPECT_MMAP_OK(mmap(NULL, getpagesize(), PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0));

  EXPECT_OK(close(cap_both));
  EXPECT_OK(close(cap_read));
  EXPECT_OK(close(cap_mmap));
  EXPECT_OK(close(cap_none));
  EXPECT_OK(close(fd));
}

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
#ifdef HAVE_SYNC_FILE_RANGE
  CHECK_RIGHT_RESULT(sync_file_range(cap_fd, 0, 1, 0), rights, CAP_FSYNC | CAP_SEEK);
#endif

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
    EXPECT_NE(0, (pollfd.revents & POLLNVAL));
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

static void TryReadWrite(int cap_fd) {
  char buffer[64];
  EXPECT_OK(read(cap_fd, buffer, sizeof(buffer)));
  int rc = write(cap_fd, "", 0);
  EXPECT_EQ(-1, rc);
  EXPECT_EQ(ENOTCAPABLE, errno);
}

FORK_TEST_ON(Capability, SocketTransfer, "/tmp/cap_fd_transfer") {
  int sock_fds[2];
  EXPECT_OK(socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds));

  struct msghdr mh;
  mh.msg_name = NULL;  // No address needed
  mh.msg_namelen = 0;
  char buffer1[1024];
  struct iovec iov[1];
  iov[0].iov_base = buffer1;
  iov[0].iov_len = sizeof(buffer1);
  mh.msg_iov = iov;
  mh.msg_iovlen = 1;
  char buffer2[1024];
  mh.msg_control = buffer2;
  mh.msg_controllen = sizeof(buffer2);
  struct cmsghdr *cmptr;

  int child = fork();
  if (child == 0) {
    // Child: enter cap mode
    EXPECT_OK(cap_enter());

    // Child: wait to receive FD over pipe
    int rc = recvmsg(sock_fds[0], &mh, 0);
    EXPECT_OK(rc);
    EXPECT_LE(CMSG_LEN(sizeof(int)), mh.msg_controllen);
    cmptr = CMSG_FIRSTHDR(&mh);
    int cap_fd = *(int*)CMSG_DATA(cmptr);
    EXPECT_EQ(CMSG_LEN(sizeof(int)), cmptr->cmsg_len);
    cmptr = CMSG_NXTHDR(&mh, cmptr);
    EXPECT_TRUE(cmptr == NULL);

    // Child: confirm we can do the right operations on the capability
    cap_rights_t rights;
    EXPECT_OK(cap_getrights(cap_fd, &rights));
    EXPECT_EQ(CAP_READ|CAP_SEEK, rights);
    TryReadWrite(cap_fd);

    // Child: wait for a normal read
    int val;
    read(sock_fds[0], &val, sizeof(val));
    exit(0);
  }

  int fd = open("/tmp/cap_fd_transfer", O_RDWR | O_CREAT, 0644);
  EXPECT_OK(fd);
  if (fd < 0) return;
  int cap_fd = cap_new(fd, CAP_READ|CAP_SEEK);

  EXPECT_OK(cap_enter());  // Enter capability mode.

  // Confirm we can do the right operations on the capability
  TryReadWrite(cap_fd);

  // Send the file descriptor over the pipe to the sub-process
  mh.msg_controllen = CMSG_LEN(sizeof(int));
  cmptr = CMSG_FIRSTHDR(&mh);
  cmptr->cmsg_level = SOL_SOCKET;
  cmptr->cmsg_type = SCM_RIGHTS;
  cmptr->cmsg_len = CMSG_LEN(sizeof(int));
  *(int *)CMSG_DATA(cmptr) = cap_fd;
  buffer1[0] = 0;
  iov[0].iov_len = 1;
  sleep(3);
  int rc = sendmsg(sock_fds[1], &mh, 0);
  EXPECT_OK(rc);

  sleep(1);  // Ensure subprocess runs
  int zero = 0;
  write(sock_fds[1], &zero, sizeof(zero));
}

TEST(Capability, SyscallAt) {
  int rc = mkdir("/tmp/cap_at_topdir", 0755);
  EXPECT_OK(rc);
  if (rc < 0 && errno != EEXIST) return;

  int dfd = open("/tmp/cap_at_topdir", O_RDONLY);
  EXPECT_OK(dfd);
  int cap_dfd_all = cap_new(dfd, CAP_LOOKUP|CAP_READ|CAP_RMDIR|CAP_MKDIR|CAP_MKFIFO);
  EXPECT_OK(cap_dfd_all);
  int cap_dfd_no_rmdir = cap_new(dfd, CAP_LOOKUP|CAP_READ|CAP_MKDIR|CAP_MKFIFO);
  EXPECT_OK(cap_dfd_no_rmdir);
  int cap_dfd_no_mkdir = cap_new(dfd, CAP_LOOKUP|CAP_READ|CAP_RMDIR|CAP_MKFIFO);
  EXPECT_OK(cap_dfd_no_mkdir);
  int cap_dfd_no_mkfifo = cap_new(dfd, CAP_LOOKUP|CAP_READ|CAP_RMDIR|CAP_MKDIR);
  EXPECT_OK(cap_dfd_no_mkfifo);

  // Need CAP_MKDIR to mkdirat(2).
  EXPECT_NOTCAPABLE(mkdirat(cap_dfd_no_mkdir, "cap_subdir", 0755));
  rmdir("/tmp/cap_at_topdir/cap_subdir");
  EXPECT_OK(mkdirat(cap_dfd_all, "cap_subdir", 0755));

  // Need CAP_RMDIR to unlinkat(dfd, name, AT_REMOVEDIR).
  EXPECT_NOTCAPABLE(unlinkat(cap_dfd_no_rmdir, "cap_subdir", AT_REMOVEDIR));
  EXPECT_OK(unlinkat(cap_dfd_all, "cap_subdir", AT_REMOVEDIR));
  rmdir("/tmp/cap_at_topdir/cap_subdir");

#ifdef OMIT
  // TODO(drydale): revisit mknod/mkfifo after sync up with FreeBSD10.x semantics
#ifdef HAVE_MKFIFOAT
  // Need CAP_MKFIFO to mkfifoat(2).
  EXPECT_NOTCAPABLE(mkfifoat(cap_dfd_no_mkfifo, "cap_fifo", 0755));
  unlink("/tmp/cap_at_topdir/cap_fifo");
  EXPECT_OK(mkfifoat(cap_dfd_all, "cap_fifo", 0755));
  unlink("/tmp/cap_at_topdir/cap_fifo");
#endif

  if (!MKNOD_REQUIRES_ROOT || getuid() == 0) {

#ifdef HAVE_MKNOD_IFREG
    // Need CAP_MKNODAT to mknodat(2) a regular file
    EXPECT_NOTCAPABLE(mknodat(cap_dfd_no_mknod, "cap_regular", S_IFREG|0755, 0));
    unlink("/tmp/cap_at_topdir/cap_regular");
    EXPECT_OK(mknodat(cap_dfd_all, "cap_regular", S_IFREG|0755, 0));
    unlink("/tmp/cap_at_topdir/cap_regular");
#endif

    // Need CAP_MKFIFO to mknodat(2) for a FIFO.
    EXPECT_NOTCAPABLE(mknodat(cap_dfd_no_mkfifo, "cap_fifo", S_IFIFO|0755, 0));
    unlink("/tmp/cap_at_topdir/cap_fifo");
    EXPECT_OK(mknodat(cap_dfd_all, "cap_fifo", S_IFIFO|0755, 0));
    unlink("/tmp/cap_at_topdir/cap_fifo");
  }
#endif

  close(cap_dfd_all);
  close(cap_dfd_no_mkfifo);
  close(cap_dfd_no_mkdir);
  close(cap_dfd_no_rmdir);
  close(dfd);

  // Tidy up.
  rmdir("/tmp/cap_at_topdir");
}
