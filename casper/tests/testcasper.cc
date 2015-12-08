#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <libcasper.h>

#include "gtest/gtest.h"

TEST(Casper, Init) {
  cap_channel_t *chan = cap_init();
  EXPECT_NE(nullptr, chan);
  cap_close(chan);
}

TEST(Casper, SocketWrap) {
  cap_channel_t *chan = cap_init();
  EXPECT_NE(nullptr, chan);

  int sock_fds[2];
  EXPECT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds));

  cap_channel_t *sock_chan = cap_wrap(sock_fds[0]);
  EXPECT_NE(nullptr, sock_chan);
  ASSERT_EQ(sock_fds[0], cap_sock(sock_chan));

  int fd = cap_unwrap(sock_chan);  // Frees sock_chan
  ASSERT_EQ(sock_fds[0], fd);

  close(sock_fds[1]);
  close(sock_fds[0]);
  cap_close(chan);
}
