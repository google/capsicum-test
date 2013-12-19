// Tests of Linux-specific functionality
#ifdef __linux__

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/fanotify.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>

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

FORK_TEST(Linux, SignalFD) {
  pid_t me = getpid();
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGUSR1);

  // Block signals before registering against a new signal FD.
  EXPECT_OK(sigprocmask(SIG_BLOCK, &mask, NULL));
  int fd = signalfd(-1, &mask, 0);
  EXPECT_OK(fd);

  // Various capability variants.
  int cap_fd_none = cap_new(fd, CAP_WRITE|CAP_SEEK);
  int cap_fd_read = cap_new(fd, CAP_READ|CAP_SEEK);
  int cap_fd_sig = cap_new(fd, CAP_FSIGNAL);
  int cap_fd_sig_read = cap_new(fd, CAP_FSIGNAL|CAP_READ|CAP_SEEK);
  int cap_fd_all = cap_new(fd, CAP_FSIGNAL|CAP_READ|CAP_SEEK|CAP_POLL_EVENT);

  struct signalfd_siginfo fdsi;

  // Need CAP_READ to read the signal information
  kill(me, SIGUSR1);
  EXPECT_NOTCAPABLE(read(cap_fd_none, &fdsi, sizeof(struct signalfd_siginfo)));
  EXPECT_NOTCAPABLE(read(cap_fd_sig, &fdsi, sizeof(struct signalfd_siginfo)));
  int len = read(cap_fd_read, &fdsi, sizeof(struct signalfd_siginfo));
  EXPECT_OK(len);
  EXPECT_EQ(sizeof(struct signalfd_siginfo), (size_t)len);
  EXPECT_EQ(SIGUSR1, (int)fdsi.ssi_signo);

  // Need CAP_FSIGNAL to modify the signal mask.
  sigemptyset(&mask);
  sigaddset(&mask, SIGUSR1);
  sigaddset(&mask, SIGUSR2);
  EXPECT_OK(sigprocmask(SIG_BLOCK, &mask, NULL));
  EXPECT_NOTCAPABLE(signalfd(cap_fd_none, &mask, 0));
  EXPECT_NOTCAPABLE(signalfd(cap_fd_read, &mask, 0));
  EXPECT_EQ(cap_fd_sig, signalfd(cap_fd_sig, &mask, 0));

  // Need CAP_POLL_EVENT to get notification of a signal in poll(2).
  kill(me, SIGUSR2);

  struct pollfd poll_fd;
  poll_fd.revents = 0;
  poll_fd.events = POLLIN;
  poll_fd.fd = cap_fd_sig_read;
  EXPECT_OK(poll(&poll_fd, 1, 400));
  EXPECT_EQ(0, (poll_fd.revents & POLLIN));
  EXPECT_NE(0, (poll_fd.revents & POLLNVAL));

  poll_fd.fd = cap_fd_all;
  EXPECT_OK(poll(&poll_fd, 1, 400));
  EXPECT_NE(0, (poll_fd.revents & POLLIN));
  EXPECT_EQ(0, (poll_fd.revents & POLLNVAL));
}

TEST(Linux, EventFD) {
  int fd = eventfd(0, 0);
  EXPECT_OK(fd);
  int cap_ro = cap_new(fd, CAP_READ|CAP_SEEK);
  int cap_wo = cap_new(fd, CAP_WRITE|CAP_SEEK);
  int cap_rw = cap_new(fd, CAP_READ|CAP_WRITE|CAP_SEEK);
  int cap_all = cap_new(fd, CAP_READ|CAP_WRITE|CAP_SEEK|CAP_POLL_EVENT);

  pid_t child = fork();
  if (child == 0) {
    // Child: write counter to eventfd
    uint64_t u = 42;
    EXPECT_NOTCAPABLE(write(cap_ro, &u, sizeof(u)));
    EXPECT_OK(write(cap_wo, &u, sizeof(u)));
    exit(HasFailure());
  }

  sleep(1);  // Allow child to write

  struct pollfd poll_fd;
  poll_fd.revents = 0;
  poll_fd.events = POLLIN;
  poll_fd.fd = cap_rw;
  EXPECT_OK(poll(&poll_fd, 1, 400));
  EXPECT_EQ(0, (poll_fd.revents & POLLIN));
  EXPECT_NE(0, (poll_fd.revents & POLLNVAL));

  poll_fd.fd = cap_all;
  EXPECT_OK(poll(&poll_fd, 1, 400));
  EXPECT_NE(0, (poll_fd.revents & POLLIN));
  EXPECT_EQ(0, (poll_fd.revents & POLLNVAL));

  uint64_t u;
  EXPECT_NOTCAPABLE(read(cap_wo, &u, sizeof(u)));
  EXPECT_OK(read(cap_ro, &u, sizeof(u)));
  EXPECT_EQ(42, (int)u);

  // Wait for the child.
  int status;
  EXPECT_EQ(child, waitpid(child, &status, 0));
  int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  EXPECT_EQ(0, rc);

  close(cap_all);
  close(cap_rw);
  close(cap_wo);
  close(cap_ro);
  close(fd);
}

TEST(Linux, epoll) {
  int sock_fds[2];
  EXPECT_OK(socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds));
  // Queue some data.
  char buffer[4] = {1, 2, 3, 4};
  EXPECT_OK(write(sock_fds[1], buffer, sizeof(buffer)));

  int epoll_fd = epoll_create(1);
  EXPECT_OK(epoll_fd);
  int cap_epoll_wo = cap_new(epoll_fd, CAP_WRITE|CAP_SEEK);
  int cap_epoll_ro = cap_new(epoll_fd, CAP_READ|CAP_SEEK);
  int cap_epoll_rw = cap_new(epoll_fd, CAP_READ|CAP_WRITE|CAP_SEEK);
  int cap_epoll_poll = cap_new(epoll_fd, CAP_READ|CAP_WRITE|CAP_SEEK|CAP_POLL_EVENT);
  int cap_epoll_ctl = cap_new(epoll_fd, CAP_EPOLL_CTL);

  // Can only modify the FDs being monitored if the CAP_EPOLL_CTL right is present.
  struct epoll_event eev;
  memset(&eev, 0, sizeof(eev));
  eev.events = EPOLLIN|EPOLLOUT|EPOLLPRI;
  EXPECT_NOTCAPABLE(epoll_ctl(cap_epoll_ro, EPOLL_CTL_ADD, sock_fds[0], &eev));
  EXPECT_NOTCAPABLE(epoll_ctl(cap_epoll_wo, EPOLL_CTL_ADD, sock_fds[0], &eev));
  EXPECT_NOTCAPABLE(epoll_ctl(cap_epoll_rw, EPOLL_CTL_ADD, sock_fds[0], &eev));
  EXPECT_OK(epoll_ctl(cap_epoll_ctl, EPOLL_CTL_ADD, sock_fds[0], &eev));
  eev.events = EPOLLIN|EPOLLOUT;
  EXPECT_NOTCAPABLE(epoll_ctl(cap_epoll_ro, EPOLL_CTL_MOD, sock_fds[0], &eev));
  EXPECT_NOTCAPABLE(epoll_ctl(cap_epoll_wo, EPOLL_CTL_MOD, sock_fds[0], &eev));
  EXPECT_NOTCAPABLE(epoll_ctl(cap_epoll_rw, EPOLL_CTL_MOD, sock_fds[0], &eev));
  EXPECT_OK(epoll_ctl(cap_epoll_ctl, EPOLL_CTL_MOD, sock_fds[0], &eev));

  // Running epoll_pwait(2) requires CAP_POLL_EVENT.
  eev.events = 0;
  EXPECT_NOTCAPABLE(epoll_pwait(cap_epoll_ro, &eev, 1, 100, NULL));
  EXPECT_NOTCAPABLE(epoll_pwait(cap_epoll_wo, &eev, 1, 100, NULL));
  EXPECT_NOTCAPABLE(epoll_pwait(cap_epoll_rw, &eev, 1, 100, NULL));
  EXPECT_OK(epoll_pwait(cap_epoll_poll, &eev, 1, 100, NULL));
  EXPECT_EQ(EPOLLIN, eev.events & EPOLLIN);

  EXPECT_NOTCAPABLE(epoll_ctl(cap_epoll_ro, EPOLL_CTL_DEL, sock_fds[0], &eev));
  EXPECT_NOTCAPABLE(epoll_ctl(cap_epoll_wo, EPOLL_CTL_DEL, sock_fds[0], &eev));
  EXPECT_NOTCAPABLE(epoll_ctl(cap_epoll_rw, EPOLL_CTL_DEL, sock_fds[0], &eev));
  EXPECT_OK(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, sock_fds[0], &eev));

  close(cap_epoll_ctl);
  close(cap_epoll_poll);
  close(cap_epoll_rw);
  close(cap_epoll_ro);
  close(cap_epoll_wo);
  close(epoll_fd);
  close(sock_fds[1]);
  close(sock_fds[0]);
  unlink("/tmp/cap_epoll");
}

// fanotify support may not be available at compile-time
#ifdef __NR_fanotify_init
TEST(Linux, fanotify) {
  if (getuid() != 0) {
    fprintf(stderr, "This test needs to be run as root; skipping\n");
    return;
  }
  int fa_fd = fanotify_init(FAN_CLASS_NOTIF, O_RDWR);
  EXPECT_OK(fa_fd);
  if (fa_fd < 0) return;  // May not be enabled

  int cap_fd_ro = cap_new(fa_fd, CAP_READ|CAP_SEEK);
  int cap_fd_wo = cap_new(fa_fd, CAP_WRITE|CAP_SEEK);
  int cap_fd_rw = cap_new(fa_fd, CAP_READ|CAP_WRITE|CAP_SEEK);
  int cap_fd_poll = cap_new(fa_fd, CAP_READ|CAP_WRITE|CAP_SEEK|CAP_POLL_EVENT);
  int cap_fd_not = cap_new(fa_fd, CAP_READ|CAP_WRITE|CAP_SEEK|CAP_NOTIFY);

  int rc = mkdir("/tmp/cap_notify", 0755);
  EXPECT_TRUE(rc == 0 || errno == EEXIST);
  int dfd = open("/tmp/cap_notify", O_RDONLY);
  EXPECT_OK(dfd);
  int cap_dfd = cap_new(dfd, CAP_READ|CAP_SEEK|CAP_LOOKUP|CAP_FSTAT);
  EXPECT_OK(cap_dfd);

  // Need CAP_NOTIFY to change what's monitored.
  EXPECT_NOTCAPABLE(fanotify_mark(cap_fd_ro, FAN_MARK_ADD, FAN_OPEN|FAN_MODIFY|FAN_EVENT_ON_CHILD, cap_dfd, NULL));
  EXPECT_NOTCAPABLE(fanotify_mark(cap_fd_wo, FAN_MARK_ADD, FAN_OPEN|FAN_MODIFY|FAN_EVENT_ON_CHILD, cap_dfd, NULL));
  EXPECT_NOTCAPABLE(fanotify_mark(cap_fd_rw, FAN_MARK_ADD, FAN_OPEN|FAN_MODIFY|FAN_EVENT_ON_CHILD, cap_dfd, NULL));
  EXPECT_OK(fanotify_mark(cap_fd_not, FAN_MARK_ADD, FAN_OPEN|FAN_MODIFY|FAN_EVENT_ON_CHILD, cap_dfd, NULL));

  pid_t child = fork();
  if (child == 0) {
    // Child: Perform activity in the directory under notify.
    sleep(1);
    unlink("/tmp/cap_notify/temp");
    int fd = open("/tmp/cap_notify/temp", O_CREAT|O_RDWR, 0644);
    close(fd);
    exit(0);
  }

  // Need CAP_POLL_EVENT to poll.
  struct pollfd poll_fd;
  poll_fd.revents = 0;
  poll_fd.events = POLLIN;
  poll_fd.fd = cap_fd_rw;
  EXPECT_OK(poll(&poll_fd, 1, 1400));
  EXPECT_EQ(0, (poll_fd.revents & POLLIN));
  EXPECT_NE(0, (poll_fd.revents & POLLNVAL));

  poll_fd.fd = cap_fd_not;
  EXPECT_OK(poll(&poll_fd, 1, 1400));
  EXPECT_EQ(0, (poll_fd.revents & POLLIN));
  EXPECT_NE(0, (poll_fd.revents & POLLNVAL));

  poll_fd.fd = cap_fd_poll;
  EXPECT_OK(poll(&poll_fd, 1, 1400));
  EXPECT_NE(0, (poll_fd.revents & POLLIN));
  EXPECT_EQ(0, (poll_fd.revents & POLLNVAL));

  // Need CAP_READ to read.
  struct fanotify_event_metadata ev;
  memset(&ev, 0, sizeof(ev));
  EXPECT_NOTCAPABLE(read(cap_fd_wo, &ev, sizeof(ev)));
  rc = read(fa_fd, &ev, sizeof(ev));
  EXPECT_OK(rc);
  EXPECT_EQ((int)sizeof(struct fanotify_event_metadata), rc);
  EXPECT_EQ(child, ev.pid);
  EXPECT_NE(0, ev.fd);

#ifdef OMIT
  // TODO(drysdale): investigate further
  // fanotify(7) gives us a FD for the changed file.  This should
  // only have rights that are a subset of those for the original
  // monitored directory file descriptor.
  cap_rights_t rights = CAP_ALL;
  EXPECT_OK(cap_getrights(ev.fd, &rights));
  EXPECT_RIGHTS_IN(rights, CAP_READ|CAP_SEEK|CAP_LOOKUP|CAP_FSTAT);
#endif

  // Wait for the child.
  int status;
  EXPECT_EQ(child, waitpid(child, &status, 0));
  rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  EXPECT_EQ(0, rc);

  close(cap_dfd);
  close(dfd);
  unlink("/tmp/cap_notify/temp");
  rmdir("/tmp/cap_notify");
  close(cap_fd_not);
  close(cap_fd_poll);
  close(cap_fd_rw);
  close(cap_fd_wo);
  close(cap_fd_ro);
  close(fa_fd);
}
#endif

TEST(Linux, inotify) {
  int i_fd = inotify_init();
  EXPECT_OK(i_fd);

  int cap_fd_ro = cap_new(i_fd, CAP_READ|CAP_SEEK);
  int cap_fd_wo = cap_new(i_fd, CAP_WRITE|CAP_SEEK);
  int cap_fd_rw = cap_new(i_fd, CAP_READ|CAP_WRITE|CAP_SEEK);
  int cap_fd_all = cap_new(i_fd, CAP_READ|CAP_WRITE|CAP_SEEK|CAP_NOTIFY);

  int fd = open("/tmp/cap_inotify", O_CREAT|O_RDWR, 0644);
  EXPECT_NOTCAPABLE(inotify_add_watch(cap_fd_rw, "/tmp/cap_inotify", IN_ACCESS|IN_MODIFY));
  int wd = inotify_add_watch(i_fd, "/tmp/cap_inotify", IN_ACCESS|IN_MODIFY);
  EXPECT_OK(wd);

  unsigned char buffer[] = {1, 2, 3, 4};
  EXPECT_OK(write(fd, buffer, sizeof(buffer)));

  struct inotify_event iev;
  memset(&iev, 0, sizeof(iev));
  EXPECT_NOTCAPABLE(read(cap_fd_wo, &iev, sizeof(iev)));
  int rc = read(cap_fd_ro, &iev, sizeof(iev));
  EXPECT_OK(rc);
  EXPECT_EQ((int)sizeof(iev), rc);
  EXPECT_EQ(wd, iev.wd);

  EXPECT_NOTCAPABLE(inotify_rm_watch(cap_fd_wo, wd));
  EXPECT_OK(inotify_rm_watch(cap_fd_all, wd));

  close(fd);
  close(cap_fd_all);
  close(cap_fd_rw);
  close(cap_fd_wo);
  close(cap_fd_ro);
  close(i_fd);
}

#else
void noop() {}
#endif
