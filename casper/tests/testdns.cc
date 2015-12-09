#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "testcasper.h"
#include <cap_dns/cap_dns.h>

class CasperDNSTest : public CasperTest {
 public:
  CasperDNSTest() : CasperTest("system.dns") { }
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
  struct hostent *info = cap_gethostbyname(chan_, name);
  EXPECT_NE(nullptr, info);
  if (verbose) print_hostent(name, info);
}

TEST_F(CasperDNSTest, GetHostByName2) {
  if (CheckSkip()) return;

  const char *name = "google.com.";
  struct hostent *info = cap_gethostbyname2(chan_, name, AF_INET);
  EXPECT_NE(nullptr, info);
  if (verbose) print_hostent(name, info);
}

TEST_F(CasperDNSTest, GetHostByNameFail) {
  if (CheckSkip()) return;

  const char *name = "google.cxxxxx.";
  struct hostent *info = cap_gethostbyname(chan_, name);
  EXPECT_EQ(nullptr, info);
  if (verbose) print_hostent(name, info);
}

TEST_F(CasperDNSTest, GetHostByAddr) {
  if (CheckSkip()) return;

  unsigned char addr[4] = {8,8,8,8};
  struct hostent *info = cap_gethostbyaddr(chan_, addr, 4, AF_INET);
  EXPECT_NE(nullptr, info);
  if (verbose) print_hostent("8.8.8.8", info);
 }

TEST_F(CasperDNSTest, GetAddrInfo) {
  if (CheckSkip()) return;

  const char *name = "google.com.";
  struct addrinfo hint;
  hint.ai_family = AF_UNSPEC;
  hint.ai_socktype = SOCK_DGRAM;
  hint.ai_protocol = 0;
  hint.ai_flags = AI_ALL|AI_CANONNAME;
  struct addrinfo *info = nullptr;
  int rc = cap_getaddrinfo(chan_, name, NULL, &hint, &info);
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

TEST_F(CasperDNSTest, GetNameInfo) {
  if (CheckSkip()) return;

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = 53;
  addr.sin_addr.s_addr = 0x08080808;
  char name[1024] = {0};
  char service[1024] = {0};
  int rc = cap_getnameinfo(chan_, (sockaddr*)&addr, sizeof(addr), name, sizeof(name),
                           service, sizeof(service), 0);
  EXPECT_EQ(0, rc);
  if (verbose) fprintf(stderr, "8.8.8.8:53 => '%s':'%s'\n", name, service);

  // Should also cope with various missing parameters
  addr.sin_port = 0;
  memset(name, 0, sizeof(name));
  memset(service, 0, sizeof(service));
  rc = cap_getnameinfo(chan_, (sockaddr*)&addr, sizeof(addr), NULL, 0,
                       service, sizeof(service), 0);
  EXPECT_EQ(0, rc);
  if (verbose) fprintf(stderr, "8.8.8.8:53 => service='%s'\n", service);

  addr.sin_port = 53;
  rc = cap_getnameinfo(chan_, (sockaddr*)&addr, sizeof(addr), name, sizeof(name), NULL, 0, 0);
  EXPECT_EQ(0, rc);
  if (verbose) fprintf(stderr, "8.8.8.8:53 => '%s'\n", name);
}

