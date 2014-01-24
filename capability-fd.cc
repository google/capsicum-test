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
  cap_rights_t r_rws;
  cap_rights_init(&r_rws, CAP_READ, CAP_WRITE, CAP_SEEK);

  int cap_fd = dup(STDOUT_FILENO);
  EXPECT_OK(cap_fd);
  EXPECT_OK(cap_rights_limit(cap_fd, &r_rws));
  if (cap_fd < 0) return;
  int rc = write(cap_fd, "OK!\n", 4);
  EXPECT_OK(rc);
  EXPECT_EQ(4, rc);
  cap_rights_t rights;
  EXPECT_OK(cap_rights_get(cap_fd, &rights));
  EXPECT_RIGHTS_EQ(&r_rws, &rights);

  // dup/dup2 should preserve rights.
  int cap_dup = dup(cap_fd);
  EXPECT_OK(cap_dup);
  EXPECT_OK(cap_rights_get(cap_dup, &rights));
  EXPECT_RIGHTS_EQ(&r_rws, &rights);
  close(cap_dup);
  EXPECT_OK(dup2(cap_fd, cap_dup));
  EXPECT_OK(cap_rights_get(cap_dup, &rights));
  EXPECT_RIGHTS_EQ(&r_rws, &rights);
  close(cap_dup);
#ifdef HAVE_DUP3
  EXPECT_OK(dup3(cap_fd, cap_dup, 0));
  EXPECT_OK(cap_rights_get(cap_dup, &rights));
  EXPECT_RIGHTS_EQ(&r_rws, &rights);
  close(cap_dup);
#endif

  // Try to get a disjoint set of rights in a sub-capability.
  cap_rights_t r_rs;
  cap_rights_init(&r_rs, CAP_READ, CAP_SEEK);
  cap_rights_t r_rsmapchmod;
  cap_rights_init(&r_rsmapchmod, CAP_READ, CAP_SEEK, CAP_MMAP, CAP_FCHMOD);
  int cap_cap_fd = dup(cap_fd);
  EXPECT_OK(cap_cap_fd);
  rc = cap_rights_limit(cap_cap_fd, &r_rsmapchmod);
  if (rc < 0) {
    // Either we fail with ENOTCAPABLE
    EXPECT_EQ(ENOTCAPABLE, errno);
  } else {
    // Or we succeed and the rights are subsetted anyway.
    EXPECT_OK(cap_rights_get(cap_cap_fd, &rights));
    EXPECT_RIGHTS_EQ(&r_rs, &rights);
    // Check in practice as well as in theory.
    EXPECT_OK(cap_enter());
    EXPECT_NOTCAPABLE(fchmod(cap_cap_fd, 0644));
    EXPECT_OK(close(cap_cap_fd));
  }
  EXPECT_OK(close(cap_fd));
}

FORK_TEST(Capability, CapEnter) {
  EXPECT_EQ(0, cap_enter());
}

FORK_TEST(Capability, BasicInterception) {
  cap_rights_t r_0;
  cap_rights_init(&r_0, 0);
  int cap_fd = dup(1);
  EXPECT_OK(cap_fd);
  EXPECT_OK(cap_rights_limit(cap_fd, &r_0));

  EXPECT_NOTCAPABLE(write(cap_fd, "", 0));

  EXPECT_OK(cap_enter());  // Enter capability mode

  EXPECT_NOTCAPABLE(write(cap_fd, "", 0));

  // Create a new capability which does have write permission
  cap_rights_t r_ws;
  cap_rights_init(&r_ws, CAP_WRITE, CAP_SEEK);
  int cap_fd2 = dup(1);
  EXPECT_OK(cap_fd2);
  EXPECT_OK(cap_rights_limit(cap_fd2, &r_ws));
  EXPECT_OK(write(cap_fd2, "", 0));

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

  cap_rights_t r_rsstat;
  cap_rights_init(&r_rsstat, CAP_READ, CAP_SEEK, CAP_FSTAT);

  int cap_fd = dup(fd);
  EXPECT_OK(cap_fd);
  EXPECT_OK(cap_rights_limit(cap_fd, &r_rsstat));
  int cap_cap_fd = dup(cap_fd);
  EXPECT_OK(cap_cap_fd);
  EXPECT_OK(cap_rights_limit(cap_cap_fd, &r_rsstat));

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

  cap_rights_t r_rl;
  cap_rights_init(&r_rl, CAP_READ, CAP_LOOKUP);

  int cap_dir = dup(dir);
  EXPECT_OK(cap_dir);
  EXPECT_OK(cap_rights_limit(cap_dir, &r_rl));

  const char *filename = "cap_openat_write_testfile";
  int file = openat(dir, filename, O_WRONLY|O_CREAT, 0644);
  EXPECT_OK(file);
  EXPECT_EQ(5, write(file, "TEST\n", 5));
  if (file >= 0) close(file);

  EXPECT_OK(cap_enter());
  file = openat(cap_dir, filename, O_RDONLY);
  EXPECT_OK(file);

  cap_rights_t rights;
  cap_rights_init(&rights, 0);
  EXPECT_OK(cap_rights_get(file, &rights));
  EXPECT_RIGHTS_EQ(&r_rl, &rights);
  if (file >= 0) close(file);

  file = openat(cap_dir, filename, O_WRONLY|O_APPEND);
  EXPECT_NOTCAPABLE(file);
  if (file > 0) close(file);

  if (dir > 0) close(dir);
  if (cap_dir > 0) close(cap_dir);
}


// Ensure that, if the capability had enough rights for the system call to
// pass, then it did. Otherwise, ensure that the errno is ENOTCAPABLE;
// capability restrictions should kick in before any other error logic.
#define CHECK_RIGHT_RESULT(result, rights, ...) do {    \
  cap_rights_t rights_needed;                           \
  cap_rights_init(&rights_needed, __VA_ARGS__);         \
  if (cap_rights_contains(&rights, &rights_needed)) {   \
    EXPECT_OK(result);                                  \
  } else {                                              \
    EXPECT_EQ(-1, result);                              \
    EXPECT_EQ(ENOTCAPABLE, errno);                      \
  }                                                     \
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
#define CHECK_RIGHT_MMAP_RESULT(result, rights, ...) do { \
  cap_rights_t rights_needed;                             \
  cap_rights_init(&rights_needed, __VA_ARGS__);           \
  if (cap_rights_contains(&rights, &rights_needed)) {     \
    EXPECT_MMAP_OK(result);                               \
  } else {                                                \
    EXPECT_MMAP_NOTCAPABLE(result);                       \
  }                                                       \
} while (0)

FORK_TEST_ON(Capability, Mmap, "/tmp/cap_mmap_operations") {
  int fd = open("/tmp/cap_mmap_operations", O_RDWR | O_CREAT, 0644);
  EXPECT_OK(fd);
  if (fd < 0) return;

  cap_rights_t r_0;
  cap_rights_init(&r_0, 0);
  cap_rights_t r_mmap;
  cap_rights_init(&r_mmap, CAP_MMAP);
  cap_rights_t r_r;
  cap_rights_init(&r_r, CAP_PREAD);
  cap_rights_t r_rmmap;
  cap_rights_init(&r_rmmap, CAP_PREAD, CAP_MMAP);

  // If we're missing a capability, it will fail.
  int cap_none = dup(fd);
  EXPECT_OK(cap_none);
  EXPECT_OK(cap_rights_limit(cap_none, &r_0));
  int cap_mmap = dup(fd);
  EXPECT_OK(cap_mmap);
  EXPECT_OK(cap_rights_limit(cap_mmap, &r_mmap));
  int cap_read = dup(fd);
  EXPECT_OK(cap_read);
  EXPECT_OK(cap_rights_limit(cap_read, &r_r));
  int cap_both = dup(fd);
  EXPECT_OK(cap_both);
  EXPECT_OK(cap_rights_limit(cap_both, &r_rmmap));

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
#define TRY_FILE_OPS(fd, ...) do {       \
  cap_rights_t rights;                   \
  cap_rights_init(&rights, __VA_ARGS__); \
  TryFileOps((fd), rights);              \
} while (0)

static void TryFileOps(int fd, cap_rights_t rights) {
  int cap_fd = dup(fd);
  EXPECT_OK(cap_fd);
  EXPECT_OK(cap_rights_limit(cap_fd, &rights));
  if (cap_fd < 0) return;

  // Check creation of a capability from a capability.
  int cap_cap_fd = dup(cap_fd);
  EXPECT_OK(cap_cap_fd);
  EXPECT_OK(cap_rights_limit(cap_cap_fd, &rights));
  EXPECT_NE(cap_fd, cap_cap_fd);
  close(cap_cap_fd);

  char ch;
  CHECK_RIGHT_RESULT(read(cap_fd, &ch, sizeof(ch)), rights, CAP_READ, CAP_SEEK_ASWAS);

  ssize_t len1 = pread(cap_fd, &ch, sizeof(ch), 0);
  CHECK_RIGHT_RESULT(len1, rights, CAP_PREAD);
  ssize_t len2 = pread(cap_fd, &ch, sizeof(ch), 0);
  CHECK_RIGHT_RESULT(len2, rights, CAP_PREAD);
  EXPECT_EQ(len1, len2);

  CHECK_RIGHT_RESULT(write(cap_fd, &ch, sizeof(ch)), rights, CAP_WRITE, CAP_SEEK_ASWAS);
  CHECK_RIGHT_RESULT(pwrite(cap_fd, &ch, sizeof(ch), 0), rights, CAP_PWRITE);
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
                          rights, CAP_MMAP, CAP_PREAD);
  CHECK_RIGHT_MMAP_RESULT(mmap(NULL, getpagesize(), PROT_WRITE, MAP_SHARED, cap_fd, 0),
                          rights, CAP_MMAP, CAP_PWRITE);
  CHECK_RIGHT_MMAP_RESULT(mmap(NULL, getpagesize(), PROT_EXEC, MAP_SHARED, cap_fd, 0),
                          rights, CAP_MMAP, CAP_MMAP_X);
  CHECK_RIGHT_MMAP_RESULT(mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, cap_fd, 0),
                          rights, CAP_MMAP, CAP_PREAD, CAP_PWRITE);
  CHECK_RIGHT_MMAP_RESULT(mmap(NULL, getpagesize(), PROT_READ | PROT_EXEC, MAP_SHARED, cap_fd, 0),
                          rights, CAP_MMAP, CAP_PREAD, CAP_MMAP_X);
  CHECK_RIGHT_MMAP_RESULT(mmap(NULL, getpagesize(), PROT_EXEC | PROT_WRITE, MAP_SHARED, cap_fd, 0),
                          rights, CAP_MMAP, CAP_MMAP_X, CAP_PWRITE);
  CHECK_RIGHT_MMAP_RESULT(mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, cap_fd, 0),
                          rights, CAP_MMAP, CAP_PREAD, CAP_PWRITE, CAP_MMAP_X);

  CHECK_RIGHT_RESULT(fsync(cap_fd), rights, CAP_FSYNC);
#ifdef HAVE_SYNC_FILE_RANGE
  CHECK_RIGHT_RESULT(sync_file_range(cap_fd, 0, 1, 0), rights, CAP_FSYNC, CAP_SEEK);
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
  if (cap_rights_is_set(&rights, CAP_POLL_EVENT)) {
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
  if (cap_rights_is_set(&rights, CAP_POLL_EVENT)) {
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
  TRY_FILE_OPS(fd, CAP_READ);
  TRY_FILE_OPS(fd, CAP_READ, CAP_SEEK);
  TRY_FILE_OPS(fd, CAP_WRITE);
  TRY_FILE_OPS(fd, CAP_WRITE, CAP_SEEK);
  TRY_FILE_OPS(fd, CAP_READ, CAP_WRITE);
  TRY_FILE_OPS(fd, CAP_READ, CAP_WRITE, CAP_SEEK);
  TRY_FILE_OPS(fd, CAP_SEEK);
  TRY_FILE_OPS(fd, CAP_FCHFLAGS);
  TRY_FILE_OPS(fd, CAP_IOCTL);
  TRY_FILE_OPS(fd, CAP_FSTAT);
  TRY_FILE_OPS(fd, CAP_MMAP);
  TRY_FILE_OPS(fd, CAP_MMAP, CAP_READ);
  TRY_FILE_OPS(fd, CAP_MMAP, CAP_WRITE);
  TRY_FILE_OPS(fd, CAP_MMAP, CAP_MMAP_X);
  TRY_FILE_OPS(fd, CAP_MMAP, CAP_READ, CAP_WRITE);
  TRY_FILE_OPS(fd, CAP_MMAP, CAP_READ, CAP_MMAP_X);
  TRY_FILE_OPS(fd, CAP_MMAP, CAP_MMAP_X, CAP_WRITE);
  TRY_FILE_OPS(fd, CAP_MMAP, CAP_READ, CAP_WRITE, CAP_MMAP_X);
  TRY_FILE_OPS(fd, CAP_FCNTL);
  TRY_FILE_OPS(fd, CAP_POLL_EVENT);
  TRY_FILE_OPS(fd, CAP_FSYNC);
  TRY_FILE_OPS(fd, CAP_FCHOWN);
  TRY_FILE_OPS(fd, CAP_FCHMOD);
  TRY_FILE_OPS(fd, CAP_FTRUNCATE);
  TRY_FILE_OPS(fd, CAP_FLOCK);
  TRY_FILE_OPS(fd, CAP_FSTATFS);
  TRY_FILE_OPS(fd, CAP_FPATHCONF);
  TRY_FILE_OPS(fd, CAP_FUTIMES);
  TRY_FILE_OPS(fd, CAP_ACL_GET);
  TRY_FILE_OPS(fd, CAP_ACL_SET);
  TRY_FILE_OPS(fd, CAP_ACL_DELETE);
  TRY_FILE_OPS(fd, CAP_ACL_CHECK);
  TRY_FILE_OPS(fd, CAP_EXTATTR_GET);
  TRY_FILE_OPS(fd, CAP_EXTATTR_SET);
  TRY_FILE_OPS(fd, CAP_EXTATTR_DELETE);
  TRY_FILE_OPS(fd, CAP_EXTATTR_LIST);
  TRY_FILE_OPS(fd, CAP_MAC_GET);
  TRY_FILE_OPS(fd, CAP_MAC_SET);

  // Socket-specific.
  TRY_FILE_OPS(fd, CAP_GETPEERNAME);
  TRY_FILE_OPS(fd, CAP_GETSOCKNAME);
  TRY_FILE_OPS(fd, CAP_ACCEPT);

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

  cap_rights_t r_rs;
  cap_rights_init(&r_rs, CAP_READ, CAP_SEEK);

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
    EXPECT_OK(cap_rights_get(cap_fd, &rights));
    EXPECT_RIGHTS_EQ(&r_rs, &rights);
    TryReadWrite(cap_fd);

    // Child: wait for a normal read
    int val;
    read(sock_fds[0], &val, sizeof(val));
    exit(0);
  }

  int fd = open("/tmp/cap_fd_transfer", O_RDWR | O_CREAT, 0644);
  EXPECT_OK(fd);
  if (fd < 0) return;
  int cap_fd = dup(fd);
  EXPECT_OK(cap_fd);
  EXPECT_OK(cap_rights_limit(cap_fd, &r_rs));

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

  cap_rights_t r_all;
  cap_rights_init(&r_all, CAP_READ, CAP_LOOKUP, CAP_UNLINKAT, CAP_MKDIRAT, CAP_MKFIFOAT);
  cap_rights_t r_no_unlink;
  cap_rights_init(&r_no_unlink, CAP_READ, CAP_LOOKUP, CAP_MKDIRAT, CAP_MKFIFOAT);
  cap_rights_t r_no_mkdir;
  cap_rights_init(&r_no_mkdir, CAP_READ, CAP_LOOKUP, CAP_UNLINKAT, CAP_MKFIFOAT);
  cap_rights_t r_no_mkfifo;
  cap_rights_init(&r_no_mkfifo, CAP_READ, CAP_LOOKUP, CAP_UNLINKAT, CAP_MKDIRAT);

  int dfd = open("/tmp/cap_at_topdir", O_RDONLY);
  EXPECT_OK(dfd);
  int cap_dfd_all = dup(dfd);
  EXPECT_OK(cap_dfd_all);
  EXPECT_OK(cap_rights_limit(cap_dfd_all, &r_all));
  int cap_dfd_no_unlink = dup(dfd);
  EXPECT_OK(cap_dfd_no_unlink);
  EXPECT_OK(cap_rights_limit(cap_dfd_no_unlink, &r_no_unlink));
  int cap_dfd_no_mkdir = dup(dfd);
  EXPECT_OK(cap_dfd_no_mkdir);
  EXPECT_OK(cap_rights_limit(cap_dfd_no_mkdir, &r_no_mkdir));
  int cap_dfd_no_mkfifo = dup(dfd);
  EXPECT_OK(cap_dfd_no_mkfifo);
  EXPECT_OK(cap_rights_limit(cap_dfd_no_mkfifo, &r_no_mkfifo));

  // Need CAP_MKDIRAT to mkdirat(2).
  EXPECT_NOTCAPABLE(mkdirat(cap_dfd_no_mkdir, "cap_subdir", 0755));
  rmdir("/tmp/cap_at_topdir/cap_subdir");
  EXPECT_OK(mkdirat(cap_dfd_all, "cap_subdir", 0755));

  // Need CAP_UNLINKAT to unlinkat(dfd, name, AT_REMOVEDIR).
  EXPECT_NOTCAPABLE(unlinkat(cap_dfd_no_unlink, "cap_subdir", AT_REMOVEDIR));
  EXPECT_OK(unlinkat(cap_dfd_all, "cap_subdir", AT_REMOVEDIR));
  rmdir("/tmp/cap_at_topdir/cap_subdir");

#ifdef __linux__
  // TODO(drydale): revisit mknod/mkfifo after sync up with FreeBSD10.x semantics
#ifdef HAVE_MKFIFOAT
  // Need CAP_MKFIFOAT to mkfifoat(2).
  EXPECT_NOTCAPABLE(mkfifoat(cap_dfd_no_mkfifo, "cap_fifo", 0755));
  unlink("/tmp/cap_at_topdir/cap_fifo");
  EXPECT_OK(mkfifoat(cap_dfd_all, "cap_fifo", 0755));
  unlink("/tmp/cap_at_topdir/cap_fifo");
#endif

  if (!MKNOD_REQUIRES_ROOT || getuid() == 0) {
#ifdef OMIT
    // TODO(drysdale): revisit after FreeBSD10.x sync
#ifdef HAVE_MKNOD_IFREG
    // Need CAP_MKNODAT to mknodat(2) a regular file
    EXPECT_NOTCAPABLE(mknodat(cap_dfd_no_mknod, "cap_regular", S_IFREG|0755, 0));
    unlink("/tmp/cap_at_topdir/cap_regular");
    EXPECT_OK(mknodat(cap_dfd_all, "cap_regular", S_IFREG|0755, 0));
    unlink("/tmp/cap_at_topdir/cap_regular");
#endif
#endif

    // Need CAP_MKFIFOAT to mknodat(2) for a FIFO.
    EXPECT_NOTCAPABLE(mknodat(cap_dfd_no_mkfifo, "cap_fifo", S_IFIFO|0755, 0));
    unlink("/tmp/cap_at_topdir/cap_fifo");
    EXPECT_OK(mknodat(cap_dfd_all, "cap_fifo", S_IFIFO|0755, 0));
    unlink("/tmp/cap_at_topdir/cap_fifo");
  }
#endif

  close(cap_dfd_all);
  close(cap_dfd_no_mkfifo);
  close(cap_dfd_no_mkdir);
  close(cap_dfd_no_unlink);
  close(dfd);

  // Tidy up.
  rmdir("/tmp/cap_at_topdir");
}

FORK_TEST_ON(Capability, ExtendedAttributes, "/tmp/cap_extattr") {
  int fd = open("/tmp/cap_extattr", O_RDONLY|O_CREAT, 0644);
  EXPECT_OK(fd);

  char buffer[1024];
  int rc = fgetxattr_(fd, "user.capsicumtest", buffer, sizeof(buffer));
  if (rc < 0 && errno == ENOTSUP) {
    fprintf(stderr, "Filesystem for /tmp doesn't support extended attributes, skipping tests\n");
    fprintf(stderr, "(need user_xattr mount option for non-root users on Linux)\n");
    close(fd);
    return;
  }

  cap_rights_t r_rws;
  cap_rights_init(&r_rws, CAP_READ, CAP_WRITE, CAP_SEEK);
  cap_rights_t r_xlist;
  cap_rights_init(&r_xlist, CAP_EXTATTR_LIST);
  cap_rights_t r_xget;
  cap_rights_init(&r_xget, CAP_EXTATTR_GET);
  cap_rights_t r_xset;
  cap_rights_init(&r_xset, CAP_EXTATTR_SET);
  cap_rights_t r_xdel;
  cap_rights_init(&r_xdel, CAP_EXTATTR_DELETE);

  int cap = dup(fd);
  EXPECT_OK(cap);
  EXPECT_OK(cap_rights_limit(cap, &r_rws));
  int cap_xlist = dup(fd);
  EXPECT_OK(cap_xlist);
  EXPECT_OK(cap_rights_limit(cap_xlist, &r_xlist));
  int cap_xget = dup(fd);
  EXPECT_OK(cap_xget);
  EXPECT_OK(cap_rights_limit(cap_xget, &r_xget));
  int cap_xset = dup(fd);
  EXPECT_OK(cap_xset);
  EXPECT_OK(cap_rights_limit(cap_xset, &r_xset));
  int cap_xdel = dup(fd);
  EXPECT_OK(cap_xdel);
  EXPECT_OK(cap_rights_limit(cap_xdel, &r_xdel));

  const char* value = "capsicum";
  int len = strlen(value) + 1;
  EXPECT_NOTCAPABLE(fsetxattr_(cap, "user.capsicumtest", value, len, 0));
  EXPECT_NOTCAPABLE(fsetxattr_(cap_xlist, "user.capsicumtest", value, len, 0));
  EXPECT_NOTCAPABLE(fsetxattr_(cap_xget, "user.capsicumtest", value, len, 0));
  EXPECT_NOTCAPABLE(fsetxattr_(cap_xdel, "user.capsicumtest", value, len, 0));
  EXPECT_OK(fsetxattr_(cap_xset, "user.capsicumtest", value, len, 0));

  EXPECT_NOTCAPABLE(flistxattr_(cap, buffer, sizeof(buffer)));
  EXPECT_NOTCAPABLE(flistxattr_(cap_xget, buffer, sizeof(buffer)));
  EXPECT_NOTCAPABLE(flistxattr_(cap_xset, buffer, sizeof(buffer)));
  EXPECT_NOTCAPABLE(flistxattr_(cap_xdel, buffer, sizeof(buffer)));
  EXPECT_OK(flistxattr_(cap_xlist, buffer, sizeof(buffer)));

  EXPECT_NOTCAPABLE(fgetxattr_(cap, "user.capsicumtest", buffer, sizeof(buffer)));
  EXPECT_NOTCAPABLE(fgetxattr_(cap_xlist, "user.capsicumtest", buffer, sizeof(buffer)));
  EXPECT_NOTCAPABLE(fgetxattr_(cap_xset, "user.capsicumtest", buffer, sizeof(buffer)));
  EXPECT_NOTCAPABLE(fgetxattr_(cap_xdel, "user.capsicumtest", buffer, sizeof(buffer)));
  EXPECT_OK(fgetxattr_(cap_xget, "user.capsicumtest", buffer, sizeof(buffer)));

  EXPECT_NOTCAPABLE(fremovexattr_(cap, "user.capsicumtest"));
  EXPECT_NOTCAPABLE(fremovexattr_(cap_xlist, "user.capsicumtest"));
  EXPECT_NOTCAPABLE(fremovexattr_(cap_xget, "user.capsicumtest"));
  EXPECT_NOTCAPABLE(fremovexattr_(cap_xset, "user.capsicumtest"));
  EXPECT_OK(fremovexattr_(cap_xdel, "user.capsicumtest"));

  close(cap_xdel);
  close(cap_xset);
  close(cap_xget);
  close(cap_xlist);
  close(cap);
  close(fd);
}
