#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "capsicum.h"
#include "syscalls.h"
#include "capsicum-test.h"

FORK_TEST_ON(Select, LotsOFileDescriptors, "/tmp/cap_select") {
  int fd = open("/tmp/cap_select", O_RDWR | O_CREAT, 0644);
  EXPECT_OK(fd);
  if (fd < 0) return;

  // Create many POLL_EVENT capabilities.
  const int kCapCount = 64;
  int cap_fd[kCapCount];
  for (int ii = 0; ii < kCapCount; ii++) {
    cap_fd[ii] = cap_new(fd, CAP_POLL_EVENT);
    EXPECT_OK(cap_fd[ii]);
  }
  int cap_rw = cap_new(fd, CAP_READ|CAP_WRITE|CAP_SEEK);
  EXPECT_OK(cap_rw);

  EXPECT_OK(cap_enter());  // Enter capability mode

  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 100;
  fd_set rset;
  FD_ZERO(&rset);
  // Add normal file descriptor and all CAP_POLL_EVENT capabilities
  FD_SET(fd, &rset);
  int maxfd = fd;
  for (int ii = 0; ii < kCapCount; ii++) {
    FD_SET(cap_fd[ii], &rset);
    if (cap_fd[ii] > maxfd) maxfd = cap_fd[ii];
  }
  fd_set wset;
  FD_ZERO(&wset);
  FD_SET(fd, &wset);
  for (int ii = 0; ii < kCapCount; ii++) {
    FD_SET(cap_fd[ii], &wset);
  }
  int ret = select(maxfd+1, &rset, &wset, NULL, &tv);
  EXPECT_OK(ret);

  // Now also include the capability with no CAP_POLL_EVENT.
  FD_ZERO(&rset);
  FD_SET(fd, &rset);
  for (int ii = 0; ii < kCapCount; ii++) {
    FD_SET(cap_fd[ii], &rset);
  }
  FD_SET(cap_rw, &rset);
  if (cap_rw > maxfd) maxfd = cap_rw;
  FD_ZERO(&wset);
  FD_SET(fd, &wset);
  for (int ii = 0; ii < kCapCount; ii++) {
    FD_SET(cap_fd[ii], &wset);
  }
  FD_SET(cap_rw, &wset);
  ret = select(maxfd+1, &rset, &wset, NULL, &tv);
  EXPECT_NOTCAPABLE(ret);
}
