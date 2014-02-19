// Test that iotl works in capability mode.
#include <sys/types.h>
#include <sys/stat.h>
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
