// Tests for socket functionality.
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <string>

#include "capsicum.h"
#include "syscalls.h"
#include "capsicum-test.h"

TEST(Socket, UnixDomain) {
  const char* socketName = "/tmp/capsicum-test.socket";
  unlink(socketName);

  pid_t child = fork();
  if (child == 0) {
    // Child process: wait for server setup
    sleep(1);

    // Create sockets
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    EXPECT_OK(sock);
    if (sock < 0) return;
    int cap_sock_rw = cap_new(sock, CAP_READ|CAP_WRITE);
    EXPECT_OK(cap_sock_rw);
    int cap_sock_all = cap_new(sock, CAP_READ|CAP_WRITE|CAP_SOCK_ALL);
    EXPECT_OK(cap_sock_all);
    close(sock);

    // Connect socket
    struct sockaddr_un un;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, socketName);
    socklen_t len = sizeof(un);
    EXPECT_NOTCAPABLE(connect(cap_sock_rw, (struct sockaddr *)&un, len));
    EXPECT_OK(connect(cap_sock_all, (struct sockaddr *)&un, len));

    exit(HasFailure());
  }

  int sock = socket(AF_UNIX, SOCK_STREAM, 0);
  EXPECT_OK(sock);
  if (sock < 0) return;

  int cap_sock_rw = cap_new(sock, CAP_READ|CAP_WRITE);
  EXPECT_OK(cap_sock_rw);
  int cap_sock_all = cap_new(sock, CAP_READ|CAP_WRITE|CAP_SOCK_ALL);
  EXPECT_OK(cap_sock_all);
  EXPECT_OK(close(sock));

  struct sockaddr_un un;
  memset(&un, 0, sizeof(un));
  un.sun_family = AF_UNIX;
  strcpy(un.sun_path, socketName);
  socklen_t len =  (sizeof(un) - sizeof(un.sun_path) + strlen(un.sun_path));

  // Can only bind the fully-capable socket.
  EXPECT_NOTCAPABLE(bind(cap_sock_rw, (struct sockaddr *)&un, len));
  EXPECT_OK(bind(cap_sock_all, (struct sockaddr *)&un, len));

  // Can only listen on the fully-capable socket.
  EXPECT_NOTCAPABLE(listen(cap_sock_rw, 3));
  EXPECT_OK(listen(cap_sock_all, 3));

  // Can only do socket operations on the fully-capable socket.
  len = sizeof(un);
  EXPECT_NOTCAPABLE(getsockname(cap_sock_rw, (struct sockaddr*)&un, &len));
  int value = 0;
  EXPECT_NOTCAPABLE(setsockopt(cap_sock_rw, SOL_SOCKET, SO_DEBUG, &value, sizeof(value)));
  len = sizeof(value);
  EXPECT_NOTCAPABLE(getsockopt(cap_sock_rw, SOL_SOCKET, SO_DEBUG, &value, &len));

  len = sizeof(un);
  memset(&un, 0, sizeof(un));
  EXPECT_OK(getsockname(cap_sock_all, (struct sockaddr*)&un, &len));
  EXPECT_EQ(AF_UNIX, un.sun_family);
  EXPECT_EQ(std::string(socketName), std::string(un.sun_path));
  value = 0;
  EXPECT_OK(setsockopt(cap_sock_all, SOL_SOCKET, SO_DEBUG, &value, sizeof(value)));
  len = sizeof(value);
  EXPECT_OK(getsockopt(cap_sock_all, SOL_SOCKET, SO_DEBUG, &value, &len));

  // Accept the incoming connection
  len = sizeof(un);
  memset(&un, 0, sizeof(un));
  EXPECT_NOTCAPABLE(accept(cap_sock_rw, (struct sockaddr *)&un, &len));
  int conn_fd = accept(cap_sock_all, (struct sockaddr *)&un, &len);
  EXPECT_OK(conn_fd);

  // Wait for the child.
  int status;
  EXPECT_EQ(child, waitpid(child, &status, 0));
  int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  EXPECT_EQ(0, rc);

  close(conn_fd);
  close(cap_sock_rw);
  close(cap_sock_all);
  unlink(socketName);
}
