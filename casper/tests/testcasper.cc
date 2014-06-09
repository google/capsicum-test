#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <libcapsicum.h>
#include <libcapsicum_service.h>
#include <libcapsicum_dns.h>

#include "gtest/gtest.h"

extern bool verbose;
extern const char *casper_sock;

TEST(Casper, Init) {
  cap_channel_t *chan = cap_init_sock(casper_sock);
  if (!chan) {
    fprintf(stderr, "Skipping test as cap_init_sock('%s') failed\n", casper_sock);
    return;
  }
  EXPECT_NE(nullptr, chan);
  cap_close(chan);
}

TEST(Casper, InitFail) {
  cap_channel_t *chan = cap_init_sock("bogus");
  EXPECT_EQ(nullptr, chan);
}

TEST(Casper, SocketWrap) {
  cap_channel_t *chan = cap_init_sock(casper_sock);
  if (!chan) {
    fprintf(stderr, "Skipping test as cap_init_sock('%s') failed\n", casper_sock);
    return;
  }

  int sock_fds[2];
  EXPECT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds));

  cap_channel_t *sock_chan = cap_wrap(sock_fds[0]);
  EXPECT_NE(nullptr, sock_chan);
  EXPECT_EQ(sock_fds[0], cap_sock(sock_chan));

  int fd = cap_unwrap(sock_chan);  // Frees sock_chan
  EXPECT_EQ(sock_fds[0], fd);

  close(sock_fds[1]);
  close(sock_fds[0]);
  cap_close(chan);
}

TEST(Casper, GetHostByName) {
  cap_channel_t *chan = cap_init_sock(casper_sock);
  if (!chan) return;

  cap_channel_t *dns_chan = cap_service_open(chan, "system.dns");
  EXPECT_NE(nullptr, dns_chan) << "Failed to open system.dns service";
  if (!dns_chan) return;
  cap_close(chan);

  const char *name = "google.com.";
  struct hostent *info = cap_gethostbyname(dns_chan, name);
  EXPECT_NE(nullptr, info);

  if (verbose && info) {
    fprintf(stderr, "'%s' -> '%s'", name, info->h_name);
    int ii = 0;
    while (info->h_addr_list && info->h_addr_list[ii]) {
      for (int jj = 0; jj < info->h_length; jj++) {
        fprintf(stderr, "%s%d", (jj>0) ? "." : ", ", (unsigned char)info->h_addr_list[ii][jj]);
      }
      ii++;
    }
    fprintf(stderr, "\n");
  }

  cap_close(dns_chan);
}
