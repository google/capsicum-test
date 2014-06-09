#include <arpa/inet.h>
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

class CasperDNSTest : public ::testing::Test {
 public:
  CasperDNSTest() : dns_chan_(nullptr) {
    cap_channel_t *chan = cap_init_sock(casper_sock);
    EXPECT_NE(nullptr, chan) << "Failed to open socket " << casper_sock;
    if (!chan) return;
    dns_chan_ = cap_service_open(chan, "system.dns");
    EXPECT_NE(nullptr, dns_chan_) << "Failed to open system.dns service";
    cap_close(chan);
  }
  bool CheckSkip() {
    if (dns_chan_ == nullptr) {
      fprintf(stderr, "Skipping test as system.dns service unavailable\n");
      return true;
    } else {
      return false;
    }
  }
  ~CasperDNSTest() {
    if (dns_chan_) cap_close(dns_chan_);
  }
 protected:
  cap_channel_t *dns_chan_;
};

static void print_hostent(const char *name, const struct hostent *info) {
  if (!info) {
    fprintf(stderr, "'%s' -> <null>\n", name);
    return;
  }
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

TEST_F(CasperDNSTest, GetHostByName) {
  if (CheckSkip()) return;

  const char *name = "google.com.";
  struct hostent *info = cap_gethostbyname(dns_chan_, name);
  EXPECT_NE(nullptr, info);
  if (verbose) print_hostent(name, info);
}

TEST_F(CasperDNSTest, GetHostByName2) {
  if (CheckSkip()) return;

  const char *name = "google.com.";
  struct hostent *info = cap_gethostbyname2(dns_chan_, name, AF_INET);
  EXPECT_NE(nullptr, info);
  if (verbose) print_hostent(name, info);
}

TEST_F(CasperDNSTest, GetHostByNameFail) {
  if (CheckSkip()) return;

  const char *name = "google.cxxxxx.";
  struct hostent *info = cap_gethostbyname(dns_chan_, name);
  EXPECT_EQ(nullptr, info);
  if (verbose) print_hostent(name, info);
}

TEST_F(CasperDNSTest, GetHostByAddr) {
  if (CheckSkip()) return;

  unsigned char addr[4] = {8,8,8,8};
  struct hostent *info = cap_gethostbyaddr(dns_chan_, addr, 4, AF_INET);
  EXPECT_NE(nullptr, info);
  if (verbose) print_hostent("8.8.8.8", info);
 }

TEST_F(CasperDNSTest, GetAddrInfo) {
  if (CheckSkip()) return;

  const char *name = "google.com.";
  struct addrinfo *info = nullptr;
  int rc = cap_getaddrinfo(dns_chan_, name, NULL, NULL, &info);
  //  int rc = getaddrinfo(           name, NULL, NULL, &info);
  EXPECT_EQ(0, rc) << " error " << gai_strerror(rc);
  EXPECT_NE(nullptr, info);
  if (verbose) {
    fprintf(stderr, "'%s' -> ", name);
    for (struct addrinfo *p = info; p != nullptr; p = p->ai_next) {
      if (p->ai_canonname) fprintf(stderr, "(%s) ", p->ai_canonname);
      if (p->ai_addr) {
        char buf[1024];
        memset(buf, 0, sizeof(buf));
        const char *result = nullptr;
        if (p->ai_family == AF_INET) {
          struct sockaddr_in *s = (struct sockaddr_in *)p->ai_addr;
          result = inet_ntop(AF_INET, &s->sin_addr, buf, sizeof(buf));
        } else if (p->ai_family == AF_INET6) {
          struct sockaddr_in6 *s = (struct sockaddr_in6 *)p->ai_addr;
          result = inet_ntop(AF_INET6, &s->sin6_addr, buf, sizeof(buf));
        }
        if (result) fprintf(stderr, "%s, ", result);
      }
    }
    fprintf(stderr, "\n");
  }
  freeaddrinfo(info);
}
