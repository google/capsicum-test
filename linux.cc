// Tests of Linux-specific functionality
#ifdef __linux__

#include <sys/timerfd.h>
#include <poll.h>

#include "capsicum.h"
#include "syscalls.h"
#include "capsicum-test.h"

TEST(Linux, TimerFD) {
  int fd = timerfd_create(CLOCK_MONOTONIC, 0);
  int cap_fd_ro = cap_new(fd, CAP_READ);
  int cap_fd_wo = cap_new(fd, CAP_WRITE);
  int cap_fd_rw = cap_new(fd, CAP_READ|CAP_WRITE);
  int cap_fd_all = cap_new(fd, CAP_READ|CAP_WRITE|CAP_POLL_EVENT);

  struct itimerspec old_ispec;
  struct itimerspec ispec;
  ispec.it_interval.tv_sec = 0;
  ispec.it_interval.tv_nsec = 0;
  ispec.it_value.tv_sec = 0;
  ispec.it_value.tv_nsec = 100000000;  // 100ms
  EXPECT_NOTCAPABLE(timerfd_settime(cap_fd_ro, 0, &ispec, NULL));
  EXPECT_NOTCAPABLE(timerfd_settime(cap_fd_wo, 0, &ispec, &old_ispec));
  EXPECT_OK(timerfd_settime(cap_fd_wo, 0, &ispec, NULL));
  EXPECT_OK(timerfd_settime(cap_fd_rw, 0, &ispec, NULL));
  EXPECT_OK(timerfd_settime(cap_fd_all, 0, &ispec, NULL));

  EXPECT_NOTCAPABLE(timerfd_gettime(cap_fd_wo, &old_ispec));
  EXPECT_OK(timerfd_gettime(cap_fd_ro, &old_ispec));
  EXPECT_OK(timerfd_gettime(cap_fd_rw, &old_ispec));
  EXPECT_OK(timerfd_gettime(cap_fd_all, &old_ispec));

  // To be able to poll() for the timer pop, still need CAP_POLL_EVENT.
  struct pollfd poll_fd;
  for (int ii = 0; ii < 3; ii++) {
    poll_fd.revents = 0;
    poll_fd.events = POLLIN;
    switch (ii) {
    case 0: poll_fd.fd = cap_fd_ro; break;
    case 1: poll_fd.fd = cap_fd_wo; break;
    case 2: poll_fd.fd = cap_fd_rw; break;
    }
    // Poll immediately returns with POLLNVAL
    EXPECT_OK(poll(&poll_fd, 1, 400));
    EXPECT_EQ(0, (poll_fd.revents & POLLIN));
    EXPECT_NE(0, (poll_fd.revents & POLLNVAL));
  }

  poll_fd.fd = cap_fd_all;
  EXPECT_OK(poll(&poll_fd, 1, 400));
  EXPECT_NE(0, (poll_fd.revents & POLLIN));
  EXPECT_EQ(0, (poll_fd.revents & POLLNVAL));

  EXPECT_OK(timerfd_gettime(cap_fd_all, &old_ispec));
  EXPECT_EQ(0, old_ispec.it_value.tv_sec);
  EXPECT_EQ(0, old_ispec.it_value.tv_nsec);
  EXPECT_EQ(0, old_ispec.it_interval.tv_sec);
  EXPECT_EQ(0, old_ispec.it_interval.tv_nsec);

  close(cap_fd_all);
  close(cap_fd_rw);
  close(cap_fd_wo);
  close(cap_fd_ro);
  close(fd);
}

#else
void noop() {}
#endif
