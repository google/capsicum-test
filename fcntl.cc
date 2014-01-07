// Test that fcntl works in capability mode.
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <string>
#include <map>

#include "capsicum.h"
#include "capsicum-test.h"
#include "syscalls.h"

// Ensure that fcntl() works consistently for both regular file descriptors and
// capability-wrapped ones.
FORK_TEST(Fcntl, Basic) {
  cap_rights_t rights = CAP_READ|CAP_FCNTL;

  typedef std::map<std::string, int> FileMap;

  // Open some files of different types, and wrap them in capabilities.
  FileMap files;
  files["file"] = open("/etc/passwd", O_RDONLY);
  EXPECT_OK(files["file"]);
  files["socket"] = socket(PF_LOCAL, SOCK_STREAM, 0);
  EXPECT_OK(files["socket"]);
  files["SHM"] = shm_open("/capsicum-test", (O_CREAT|O_RDWR), 0600);
  if ((files["SHM"] == -1) && errno == ENOSYS) {
    // shm_open() is not implemented in user-mode Linux.
    files.erase("SHM");
  } else {
    EXPECT_OK(files["SHM"]);
  }

  FileMap caps;
  for (FileMap::iterator ii = files.begin(); ii != files.end(); ++ii) {
    caps[ii->first + " cap"] = cap_new(ii->second, rights);
    EXPECT_OK(caps[ii->first]) << " on " << ii->first;
  }

  FileMap all(files);
  all.insert(files.begin(), files.end());

  EXPECT_OK(cap_enter());  // Enter capability mode.

  // Ensure that we can fcntl() all the files that we opened above.
  for (FileMap::iterator ii = all.begin(); ii != all.end(); ++ii) {
    EXPECT_OK(fcntl(ii->second, F_GETFL, 0)) << " on " << ii->first;
    int cap = cap_new(ii->second, CAP_READ);
    EXPECT_OK(cap) << " on " << ii->first;
    EXPECT_EQ(-1, fcntl(cap, F_GETFL, 0)) << " on " << ii->first;
    EXPECT_EQ(ENOTCAPABLE, errno) << " on " << ii->first;
    close(cap);
  }
  for (FileMap::iterator ii = all.begin(); ii != all.end(); ++ii) {
    close(ii->second);
  }
  shm_unlink("/capsicum-test");
}

// Supported fcntl(2) operations:
//   FreeBSD9.1:  Linux3.11:       Rights:            Summary:
//   F_DUPFD      F_DUPFD          NONE               as dup(2)
//                F_DUPFD_CLOEXEC  NONE               as dup(2) with close-on-exec
//   F_DUP2FD                      NONE               as dup2(2)
//   F_GETFD      F_GETFD          NONE               get close-on-exec flag
//   F_SETFD      F_SETFD          NONE               set close-on-exec flag
//   F_GETFL      F_GETFL          FCNTL              get file status flag
//   F_SETFL      F_SETFL          FCNTL              set file status flag
//   F_GETOWN     F_GETOWN         FCNTL              get pid receiving SIGIO/SIGURG
//   F_SETOWN     F_SETOWN         FCNTL              set pid receiving SIGIO/SIGURG
//                F_GETOWN_EX      FCNTL              get pid/thread receiving SIGIO/SIGURG
//                F_SETOWN_EX      FCNTL              set pid/thread receiving SIGIO/SIGURG
//   F_GETLK      F_GETLK          FLOCK              get lock info
//   F_SETLK      F_SETLK          FLOCK              set lock info
//   F_SETLKW     F_SETLKW         FLOCK              set lock info (blocking)
//   F_READAHEAD                   NONE               set or clear readahead amount
//   F_RDAHEAD                     NONE               set or clear readahead amount to 128KB
//                F_GETSIG         POLL_EVENT|FSIGNAL get signal sent when I/O possible
//                F_SETSIG         POLL_EVENT_FSIGNAL set signal sent when I/O possible
//                F_GETLEASE       FLOCK|FSIGNAL      get lease on file descriptor
//                F_SETLEASE       FLOCK|FSIGNAL      set new lease on file descriptor
//                F_NOTIFY         NOTIFY             generate signal on changes (dnotify)
//                F_GETPIPE_SZ     GETSOCKOPT         get pipe size
//                F_SETPIPE_SZ     SETSOCKOPT         set pipe size
namespace {
#define FCNTL_NUM_RIGHTS 9
cap_rights_t fcntl_rights[FCNTL_NUM_RIGHTS] = {
  0,  // Later code assumes this is at [0]
  CAP_READ|CAP_WRITE,
  CAP_FCNTL,
  CAP_FLOCK,
#ifdef CAP_FSIGNAL
  CAP_POLL_EVENT|CAP_FSIGNAL,
  CAP_FLOCK|CAP_FSIGNAL,
#endif
#ifdef CAP_NOTIFY
  CAP_NOTIFY,
#endif
  CAP_SETSOCKOPT,
  CAP_GETSOCKOPT,
};
int CheckFcntl(cap_rights_t rights, int caps[FCNTL_NUM_RIGHTS], int cmd, long arg,
               const char* context) {
  SCOPED_TRACE(context);
  int ok_index = -1;
  for (int ii = 0; ii < FCNTL_NUM_RIGHTS; ++ii) {
    if (rights == (fcntl_rights[ii] & rights)) {
      if (ok_index == -1) ok_index = ii;
      continue;
    }
    EXPECT_NOTCAPABLE(fcntl(caps[ii], cmd, arg));
  }
  EXPECT_NE(-1, ok_index);
  int rc = fcntl(caps[ok_index], cmd, arg);
  EXPECT_OK(rc);
  return rc;
}
}  // namespace

#define CHECK_FCNTL(rights, caps, cmd, arg) \
    CheckFcntl(rights, caps, cmd, arg, "fcntl(" #cmd ") expect " #rights)

TEST(Fcntl, Commands) {
  int fd = open("/tmp/cap_fcntl_cmds", O_RDWR|O_CREAT, 0644);
  EXPECT_OK(fd);
  write(fd, "TEST", 4);
  int sock = socket(PF_LOCAL, SOCK_STREAM, 0);
  EXPECT_OK(sock);
  int caps[FCNTL_NUM_RIGHTS];
  int sock_caps[FCNTL_NUM_RIGHTS];
  for (int ii = 0; ii < FCNTL_NUM_RIGHTS; ++ii) {
    caps[ii] = cap_new(fd, fcntl_rights[ii]);
    EXPECT_OK(caps[ii]);
    sock_caps[ii] = cap_new(sock, fcntl_rights[ii]);
    EXPECT_OK(sock_caps[ii]);
  }

  // Check the things that need no rights against caps[0].
  int newfd = fcntl(caps[0], F_DUPFD, 0);
  EXPECT_OK(newfd);
  // dup()'ed FD should have same rights.
  cap_rights_t rights = 0UL;
  EXPECT_OK(cap_getrights(newfd, &rights));
  EXPECT_EQ(0UL, rights);
  close(newfd);
#ifdef HAVE_F_DUP2FD
  EXPECT_OK(fcntl(caps[0], F_DUP2FD, newfd));
  // dup2()'ed FD should have same rights.
  EXPECT_OK(cap_getrights(newfd, &rights));
  EXPECT_EQ(0UL, rights);
  close(newfd);
#endif

  EXPECT_OK(fcntl(caps[0], F_GETFD, 0));
  EXPECT_OK(fcntl(caps[0], F_SETFD, 0));

  // Check operations that need CAP_FCNTL.
  int fd_flag = CHECK_FCNTL(CAP_FCNTL, caps, F_GETFL, 0);
  EXPECT_EQ(0, CHECK_FCNTL(CAP_FCNTL, caps, F_SETFL, fd_flag));
  int owner = CHECK_FCNTL(CAP_FCNTL, sock_caps, F_GETOWN, 0);
  EXPECT_EQ(0, CHECK_FCNTL(CAP_FCNTL, sock_caps, F_SETOWN, owner));

  // Check an operation needing CAP_FLOCK.
  struct flock fl;
  memset(&fl, 0, sizeof(fl));
  fl.l_type = F_RDLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  fl.l_len = 1;
  EXPECT_EQ(0, CHECK_FCNTL(CAP_FLOCK, caps, F_GETLK, (long)&fl));

  for (int ii = 0; ii < FCNTL_NUM_RIGHTS; ++ii) {
    close(sock_caps[ii]);
    close(caps[ii]);
  }
  close(sock);
  close(fd);
  unlink("/tmp/cap_fcntl_cmds");
}
