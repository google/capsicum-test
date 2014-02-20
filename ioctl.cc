// Test that iotl works in capability mode.
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "capsicum.h"
#include "capsicum-test.h"

// Ensure that ioctl() works consistently for both regular file descriptors and
// capability-wrapped ones.
TEST(Ioctl, Basic) {
  cap_rights_t rights_ioctl;
  cap_rights_init(&rights_ioctl, CAP_IOCTL);
  cap_rights_t rights_many;
  cap_rights_init(&rights_many, CAP_READ, CAP_WRITE, CAP_SEEK, CAP_FSTAT, CAP_FSYNC);

  int fd = open("/etc/passwd", O_RDONLY);
  EXPECT_OK(fd);
  int fd_no = dup(fd);
  EXPECT_OK(fd_no);
  EXPECT_OK(cap_rights_limit(fd, &rights_ioctl));
  EXPECT_OK(cap_rights_limit(fd_no, &rights_many));

  // Check that CAP_IOCTL is required.
  int bytes;
  EXPECT_OK(ioctl(fd, FIONREAD, &bytes));
  EXPECT_NOTCAPABLE(ioctl(fd_no, FIONREAD, &bytes));

  int one = 1;
  EXPECT_OK(ioctl(fd, FIOCLEX, &one));
  EXPECT_NOTCAPABLE(ioctl(fd_no, FIOCLEX, &one));

  close(fd);
  close(fd_no);
}

#ifdef HAVE_CAP_IOCTLS_LIMIT
TEST(Ioctl, SubRightNormalFD) {
  int fd = open("/etc/passwd", O_RDONLY);
  EXPECT_OK(fd);

  // Restrict the ioctl(2) subrights of a normal FD.
  unsigned long ioctl_nread = FIONREAD;
  EXPECT_OK(cap_ioctls_limit(fd, &ioctl_nread, 1));
  int bytes;
  EXPECT_OK(ioctl(fd, FIONREAD, &bytes));
  int one = 1;
  EXPECT_NOTCAPABLE(ioctl(fd, FIOCLEX, &one));

  // Expect to have all capabilities.
  cap_rights_t rights;
  EXPECT_OK(cap_rights_get(fd, &rights));
  cap_rights_t all;
  CAP_ALL(&all);
  EXPECT_RIGHTS_EQ(&all, &rights);
  unsigned long ioctls[16];
  memset(ioctls, 0, sizeof(ioctls));
  ssize_t nioctls = cap_ioctls_get(fd, ioctls, 16);
  EXPECT_OK(nioctls);
  EXPECT_EQ(1, nioctls);
  EXPECT_EQ(FIONREAD, ioctls[0]);

  // Can't widen the subrights.
  unsigned long both_ioctls[2] = {FIONREAD, FIOCLEX};
  EXPECT_NOTCAPABLE(cap_ioctls_limit(fd, both_ioctls, 2));

  close(fd);
}

TEST(Ioctl, SubRights) {
  int fd = open("/etc/passwd", O_RDONLY);
  EXPECT_OK(fd);

  unsigned long ioctls[16];
  ssize_t nioctls;
  memset(ioctls, 0, sizeof(ioctls));
  nioctls = cap_ioctls_get(fd, ioctls, 16);
  EXPECT_OK(nioctls);
  EXPECT_EQ(CAP_IOCTLS_ALL, nioctls);

  cap_rights_t rights_ioctl;
  cap_rights_init(&rights_ioctl, CAP_IOCTL);
  EXPECT_OK(cap_rights_limit(fd, &rights_ioctl));

  nioctls = cap_ioctls_get(fd, ioctls, 16);
  EXPECT_OK(nioctls);
  EXPECT_EQ(CAP_IOCTLS_ALL, nioctls);

  // Check operations that need CAP_IOCTL with subrights pristine => OK.
  int bytes;
  EXPECT_OK(ioctl(fd, FIONREAD, &bytes));
  int one = 1;
  EXPECT_OK(ioctl(fd, FIOCLEX, &one));

  // Check operations that need CAP_IOCTL with all relevant subrights => OK.
  unsigned long both_ioctls[2] = {FIONREAD, FIOCLEX};
  EXPECT_OK(cap_ioctls_limit(fd, both_ioctls, 2));
  EXPECT_OK(ioctl(fd, FIONREAD, &bytes));
  EXPECT_OK(ioctl(fd, FIOCLEX, &one));

  // Check operations that need CAP_IOCTL with particular subrights.
  int fd_nread = dup(fd);
  int fd_clex = dup(fd);
  unsigned long ioctl_nread = FIONREAD;
  unsigned long ioctl_clex = FIOCLEX;
  EXPECT_OK(cap_ioctls_limit(fd_nread, &ioctl_nread, 1));
  EXPECT_OK(cap_ioctls_limit(fd_clex, &ioctl_clex, 1));
  EXPECT_OK(ioctl(fd_nread, FIONREAD, &bytes));
  EXPECT_NOTCAPABLE(ioctl(fd_clex, FIONREAD, &bytes));
  EXPECT_OK(ioctl(fd_clex, FIOCLEX, &one));
  EXPECT_NOTCAPABLE(ioctl(fd_nread, FIOCLEX, &one));

  // Also check we can retrieve the subrights.
  memset(ioctls, 0, sizeof(ioctls));
  nioctls = cap_ioctls_get(fd_nread, ioctls, 16);
  EXPECT_OK(nioctls);
  EXPECT_EQ(1, nioctls);
  EXPECT_EQ(FIONREAD, ioctls[0]);
  memset(ioctls, 0, sizeof(ioctls));
  nioctls = cap_ioctls_get(fd_clex, ioctls, 16);
  EXPECT_OK(nioctls);
  EXPECT_EQ(1, nioctls);
  EXPECT_EQ(FIOCLEX, ioctls[0]);
  // And that we can't widen the subrights.
  EXPECT_NOTCAPABLE(cap_ioctls_limit(fd_nread, both_ioctls, 2));
  EXPECT_NOTCAPABLE(cap_ioctls_limit(fd_clex, both_ioctls, 2));
  close(fd_nread);
  close(fd_clex);

  // Check operations that need CAP_IOCTL with no subrights => ENOTCAPABLE.
  EXPECT_OK(cap_ioctls_limit(fd, NULL, 0));
  EXPECT_NOTCAPABLE(ioctl(fd, FIONREAD, &bytes));
  EXPECT_NOTCAPABLE(ioctl(fd, FIOCLEX, &one));

  close(fd);
  unlink("/tmp/cap_fcntl_cmds");
}
#endif
