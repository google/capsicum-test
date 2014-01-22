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
  cap_rights_t rights;
  cap_rights_init(&rights, CAP_READ, CAP_FCNTL);

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
    std::string key = ii->first + " cap";
    caps[key] = dup(ii->second);
    EXPECT_OK(cap_rights_limit(caps[key], &rights));
    EXPECT_OK(caps[key]) << " on " << ii->first;
  }

  FileMap all(files);
  all.insert(files.begin(), files.end());

  EXPECT_OK(cap_enter());  // Enter capability mode.

  // Ensure that we can fcntl() all the files that we opened above.
  cap_rights_t r_ro;
  cap_rights_init(&r_ro, CAP_READ);
  for (FileMap::iterator ii = all.begin(); ii != all.end(); ++ii) {
    EXPECT_OK(fcntl(ii->second, F_GETFL, 0)) << " on " << ii->first;
    int cap = dup(ii->second);
    EXPECT_OK(cap) << " on " << ii->first;
    EXPECT_OK(cap_rights_limit(cap, &r_ro)) << " on " << ii->first;
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
cap_rights_t fcntl_rights[FCNTL_NUM_RIGHTS];
void InitRights() {
  cap_rights_init(&(fcntl_rights[0]), 0);  // Later code assumes this is at [0]
  cap_rights_init(&(fcntl_rights[1]), CAP_READ, CAP_WRITE);
  cap_rights_init(&(fcntl_rights[2]), CAP_FCNTL);
  cap_rights_init(&(fcntl_rights[3]), CAP_FLOCK);
#ifdef CAP_FSIGNAL
  cap_rights_init(&(fcntl_rights[4]), CAP_POLL_EVENT, CAP_FSIGNAL);
  cap_rights_init(&(fcntl_rights[5]), CAP_FLOCK, CAP_FSIGNAL);
#else
  cap_rights_init(&(fcntl_rights[4]), 0);
  cap_rights_init(&(fcntl_rights[5]), 0);
#endif
#ifdef CAP_NOTIFY
  cap_rights_init(&(fcntl_rights[6]), CAP_NOTIFY);
#else
  cap_rights_init(&(fcntl_rights[6]), 0);
#endif
  cap_rights_init(&(fcntl_rights[7]), CAP_SETSOCKOPT);
  cap_rights_init(&(fcntl_rights[8]), CAP_GETSOCKOPT);
}

int CheckFcntl(unsigned long long right, int caps[FCNTL_NUM_RIGHTS], int cmd, long arg, const char* context) {
  SCOPED_TRACE(context);
  cap_rights_t rights;
  cap_rights_init(&rights, right);
  int ok_index = -1;
  for (int ii = 0; ii < FCNTL_NUM_RIGHTS; ++ii) {
    if (cap_rights_contains(&(fcntl_rights[ii]), &rights)) {
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

#define CHECK_FCNTL(right, caps, cmd, arg) \
    CheckFcntl(right, caps, cmd, arg, "fcntl(" #cmd ") expect " #right)

TEST(Fcntl, Commands) {
  InitRights();
  int fd = open("/tmp/cap_fcntl_cmds", O_RDWR|O_CREAT, 0644);
  EXPECT_OK(fd);
  write(fd, "TEST", 4);
  int sock = socket(PF_LOCAL, SOCK_STREAM, 0);
  EXPECT_OK(sock);
  int caps[FCNTL_NUM_RIGHTS];
  int sock_caps[FCNTL_NUM_RIGHTS];
  for (int ii = 0; ii < FCNTL_NUM_RIGHTS; ++ii) {
    caps[ii] = dup(fd);
    EXPECT_OK(caps[ii]);
    EXPECT_OK(cap_rights_limit(caps[ii], &(fcntl_rights[ii])));
    sock_caps[ii] = dup(sock);
    EXPECT_OK(sock_caps[ii]);
    EXPECT_OK(cap_rights_limit(sock_caps[ii], &(fcntl_rights[ii])));
  }

  // Check the things that need no rights against caps[0].
  int newfd = fcntl(caps[0], F_DUPFD, 0);
  EXPECT_OK(newfd);
  // dup()'ed FD should have same rights.
  cap_rights_t rights;
  cap_rights_init(&rights, 0);
  EXPECT_OK(cap_rights_get(newfd, &rights));
  EXPECT_TRUE(cap_rights_contains(&(fcntl_rights[0]), &rights));
  EXPECT_TRUE(cap_rights_contains(&rights, &(fcntl_rights[0])));
  close(newfd);
#ifdef HAVE_F_DUP2FD
  EXPECT_OK(fcntl(caps[0], F_DUP2FD, newfd));
  // dup2()'ed FD should have same rights.
  EXPECT_OK(cap_rights_get(newfd, &rights));
  EXPECT_TRUE(cap_rights_contains(&(fcntl_rights[0]), &rights));
  EXPECT_TRUE(cap_rights_contains(&rights, &(fcntl_rights[0])));
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
