// Tests of SCTP functionality
// Requires: libsctp-dev package on Debian Linux, CONFIG_IP_SCTP in kernel config
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>

#include "capsicum.h"
#include "capsicum-test.h"

TEST(Sctp, Socket) {
  int sock = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
  EXPECT_OK(sock);
  if (sock < 0) return;

  cap_rights_t r_ro;
  cap_rights_init(&r_ro, CAP_READ);
  cap_rights_t r_wo;
  cap_rights_init(&r_wo, CAP_WRITE);
  cap_rights_t r_rw;
  cap_rights_init(&r_rw, CAP_READ, CAP_WRITE);
  cap_rights_t r_all;
  cap_rights_init(&r_all, CAP_READ, CAP_WRITE, CAP_SOCK_CLIENT, CAP_SOCK_SERVER);

  int cap_sock_wo = dup(sock);
  EXPECT_OK(cap_sock_wo);
  EXPECT_OK(cap_rights_limit(cap_sock_wo, &r_wo));
  int cap_sock_rw = dup(sock);
  EXPECT_OK(cap_sock_rw);
  EXPECT_OK(cap_rights_limit(cap_sock_rw, &r_rw));
  int cap_sock_all = dup(sock);
  EXPECT_OK(cap_sock_all);
  EXPECT_OK(cap_rights_limit(cap_sock_all, &r_all));
  close(sock);

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(0);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  socklen_t len = sizeof(addr);

  // Can only bind the fully-capable socket.
  EXPECT_NOTCAPABLE(bind(cap_sock_rw, (struct sockaddr *)&addr, len));
  EXPECT_OK(bind(cap_sock_all, (struct sockaddr *)&addr, len));

  EXPECT_OK(getsockname(cap_sock_all, (struct sockaddr *)&addr, &len));
  int port = ntohs(addr.sin_port);

  // Now we know the port involved, fork off a child.
  pid_t child = fork();
  if (child == 0) {
    // Child process: wait for server setup
    sleep(1);

    // Create sockets
    int sock = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
    EXPECT_OK(sock);
    if (sock < 0) return;
    int cap_sock_ro = dup(sock);
    EXPECT_OK(cap_sock_ro);
    EXPECT_OK(cap_rights_limit(cap_sock_ro, &r_rw));
    int cap_sock_rw = dup(sock);
    EXPECT_OK(cap_sock_rw);
    EXPECT_OK(cap_rights_limit(cap_sock_rw, &r_rw));
    int cap_sock_all = dup(sock);
    EXPECT_OK(cap_sock_all);
    EXPECT_OK(cap_rights_limit(cap_sock_all, &r_all));
    close(sock);

    // Send a message.  Requires CAP_WRITE and CAP_CONNECT
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(port);
    unsigned char byte = 99;

    EXPECT_NOTCAPABLE(sctp_sendmsg(cap_sock_ro, &byte, 1, (struct sockaddr*)&serv_addr, sizeof(serv_addr),
                                   1, 0, 1, 0, 0));
    EXPECT_NOTCAPABLE(sctp_sendmsg(cap_sock_rw, &byte, 1, (struct sockaddr*)&serv_addr, sizeof(serv_addr),
                           1, 0, 1, 0, 0));
    EXPECT_OK(sctp_sendmsg(cap_sock_all, &byte, 1, (struct sockaddr*)&serv_addr, sizeof(serv_addr),
                           1, 0, 1, 0, 0));
    close(cap_sock_ro);
    close(cap_sock_rw);
    close(cap_sock_all);
    exit(HasFailure());
  }

  // Can only listen on the fully-capable socket.
  EXPECT_NOTCAPABLE(listen(cap_sock_rw, 3));
  EXPECT_OK(listen(cap_sock_all, 3));

  // Can only do socket operations on the fully-capable socket.
  len = sizeof(addr);
  EXPECT_NOTCAPABLE(getsockname(cap_sock_rw, (struct sockaddr*)&addr, &len));
  int value = 1;
  EXPECT_NOTCAPABLE(setsockopt(cap_sock_rw, SOL_SOCKET, SO_REUSEPORT, &value, sizeof(value)));
  len = sizeof(value);
  EXPECT_NOTCAPABLE(getsockopt(cap_sock_rw, SOL_SOCKET, SO_REUSEPORT, &value, &len));

  struct sctp_event_subscribe events;
  events.sctp_association_event = 1;
  events.sctp_data_io_event = 1;
  EXPECT_NOTCAPABLE(setsockopt(cap_sock_rw, IPPROTO_SCTP, SCTP_EVENTS, &events, sizeof(events)));
  len = sizeof(events);
  EXPECT_NOTCAPABLE(getsockopt(cap_sock_rw, IPPROTO_SCTP, SCTP_EVENTS, &events, &len));

  len = sizeof(addr);
  memset(&addr, 0, sizeof(addr));
  EXPECT_OK(getsockname(cap_sock_all, (struct sockaddr*)&addr, &len));
  EXPECT_EQ(AF_INET, addr.sin_family);
  EXPECT_EQ(htons(port), addr.sin_port);

  struct sockaddr_in client_addr;
  socklen_t addr_len = sizeof(client_addr);
  char buffer[1024];
  struct sctp_sndrcvinfo sri;
  int flags;
  EXPECT_NOTCAPABLE(sctp_recvmsg(cap_sock_wo, buffer, sizeof(buffer), (struct sockaddr*)&client_addr, &addr_len, &sri, &flags));
  while (true) {
    int len = sctp_recvmsg(cap_sock_rw, buffer, sizeof(buffer), (struct sockaddr*)&client_addr, &addr_len, &sri, &flags);
    EXPECT_OK(len);
    if (len < 0) break;
    if (len > 0 && buffer[0] == 99) break;
  }

  // Wait for the child.
  int status;
  EXPECT_EQ(child, waitpid(child, &status, 0));
  int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  EXPECT_EQ(0, rc);

  close(cap_sock_wo);
  close(cap_sock_rw);
  close(cap_sock_all);
}
