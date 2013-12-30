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

  EXPECT_OK(cap_enter());

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
