/*-
 * Copyright (c) 2009-2011 Robert N. M. Watson
 * Copyright (c) 2011 Jonathan Anderson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Test that fcntl works in capability mode.
 */

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
  // Note that shm_open is not implemented in user-mode Linux.
  files["SHM"] = shm_open("/capsicum-test", (O_CREAT|O_RDWR), 0600);
  EXPECT_OK(files["SHM"]);

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
