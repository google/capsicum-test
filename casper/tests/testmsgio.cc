#include "nv.h"
#include "msgio.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

#include <string>

#include "gtest/gtest.h"

extern bool verbose;

TEST(NVList, CredSend) {
  int fds[2];
  EXPECT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

#ifdef	__linux__
  // Need to turn on SO_PASSCRED before the fork(); for some reason, turning
  // it on afterwards doesn't work (and credentials are always returned as
  // 65534/65534)
  int one = 1;
  EXPECT_EQ(0, setsockopt(fds[0], SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)));
#endif

  pid_t child = fork();
  if (child == 0) {
    // Child: wait to receive credentials.
    uid_t uid;
    gid_t gid;
    gid_t groups[10];
    int ngroups = 10;
    EXPECT_EQ(0, cred_recv(fds[0], &uid, &gid, &ngroups, groups));
    EXPECT_EQ(getuid(), uid);
    EXPECT_EQ(getgid(), gid);
    exit(HasFailure());
  }

  // Send credentials down the socket.
  EXPECT_EQ(0, cred_send(fds[1]));

  // Wait for the child.
  int status;
  EXPECT_EQ(child, waitpid(child, &status, 0));
  EXPECT_TRUE(WIFEXITED(status)) << " status " << status;
  EXPECT_EQ(0, WEXITSTATUS(status));

  close(fds[1]);
  close(fds[0]);
}

