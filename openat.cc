#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "capsicum.h"
#include "capsicum-test.h"

// Check an open call works and close the resulting fd.
#define EXPECT_OPEN_OK(f) do { \
    int fd = f;                \
    EXPECT_OK(fd);             \
    close(fd);                 \
  } while (0)


// Test openat(2) in a variety of sitations to ensure that it obeys Capsicum
// "strict relative" rules:
//
// 1. Use strict relative lookups in capability mode or when operating
//    relative to a capability.
// 2. When performing strict relative lookups, absolute paths (including
//    symlinks to absolute paths) are not allowed, nor are paths containing
//    '..' components.
FORK_TEST(Openat, Relative) {
  int etc = open("/etc/", O_RDONLY);
  EXPECT_OK(etc);

  cap_rights_t rights;
  EXPECT_SYSCALL_FAIL(EINVAL, cap_getrights(etc, &rights));

  cap_rights_t baserights = (CAP_READ | CAP_WRITE | CAP_SEEK | CAP_LOOKUP);
  int etc_cap = cap_new(etc, CAP_READ);
  EXPECT_OK(etc_cap);
  int etc_cap_ro = cap_new(etc, CAP_READ | CAP_LOOKUP);
  EXPECT_OK(etc_cap_ro);
  int etc_cap_base = cap_new(etc, baserights);
  EXPECT_OK(etc_cap_base);
  int etc_cap_all = cap_new(etc, CAP_MASK_VALID);
  EXPECT_OK(etc_cap_all);

  // openat(2) with regular file descriptors in non-capability mode
  // Should Just Work (tm).
  EXPECT_OPEN_OK(openat(etc, "/etc/passwd", O_RDONLY));
  EXPECT_OPEN_OK(openat(AT_FDCWD, "/etc/passwd", O_RDONLY));
  EXPECT_OPEN_OK(openat(etc, "passwd", O_RDONLY));
  EXPECT_OPEN_OK(openat(etc, "../etc/passwd", O_RDONLY));

  // Lookups relative to capabilities should be strictly relative.
  // When not in capability mode, we don't actually require CAP_LOOKUP.
  EXPECT_OPEN_OK(openat(etc_cap_ro, "passwd", O_RDONLY));
  EXPECT_OPEN_OK(openat(etc_cap_base, "passwd", O_RDONLY));
  EXPECT_OPEN_OK(openat(etc_cap_all, "passwd", O_RDONLY));

  // Performing openat(2) on a path with leading slash ignores
  // the provided directory FD.
  EXPECT_OPEN_OK(openat(etc_cap_ro, "/etc/passwd", O_RDONLY));
  EXPECT_OPEN_OK(openat(etc_cap_base, "/etc/passwd", O_RDONLY));
  // Relative lookups that go upward are not allowed.
  EXPECT_NOTCAPABLE(openat(etc_cap_ro, "../etc/passwd", O_RDONLY));
  EXPECT_NOTCAPABLE(openat(etc_cap_base, "../etc/passwd", O_RDONLY));

  // This requires discussion: do we treat a capability with
  // CAP_MASK_VALID *exactly* like a non-capability file descriptor?
  // (currently, the FreeBSD implementation says yes)
  if (CAP_MASK_VALID_IS_UNCHECKED) {
    EXPECT_OPEN_OK(openat(etc_cap_all, "../etc/passwd", O_RDONLY));
  } else {
    EXPECT_NOTCAPABLE(openat(etc_cap_all, "../etc/passwd", O_RDONLY));
  }

  // A file opened relative to a capability should itself be a capability.
  int fd = openat(etc_cap_base, "passwd", O_RDONLY);
  EXPECT_OK(fd);
  EXPECT_OK(cap_getrights(fd, &rights));
  EXPECT_RIGHTS_IN(rights, baserights);
  close(fd);

  // Enter capability mode; now ALL lookups are strictly relative.
  EXPECT_OK(cap_enter());

  // Relative lookups on regular files or capabilities with CAP_LOOKUP
  // ought to succeed.
  EXPECT_OPEN_OK(openat(etc, "passwd", O_RDONLY));
  EXPECT_OPEN_OK(openat(etc_cap_ro, "passwd", O_RDONLY));
  EXPECT_OPEN_OK(openat(etc_cap_base, "passwd", O_RDONLY));
  EXPECT_OPEN_OK(openat(etc_cap_all, "passwd", O_RDONLY));

  // Lookup relative to capabilities without CAP_LOOKUP should fail.
  EXPECT_NOTCAPABLE(openat(etc_cap, "passwd", O_RDONLY));

  // Absolute lookups should fail.
  EXPECT_CAPMODE(openat(AT_FDCWD, "/etc/passwd", O_RDONLY));
  EXPECT_NOTCAPABLE(openat(etc, "/etc/passwd", O_RDONLY));
  EXPECT_NOTCAPABLE(openat(etc_cap_ro, "/etc/passwd", O_RDONLY));

  // Lookups containing '..' should fail in capability mode.
  EXPECT_NOTCAPABLE(openat(etc, "../etc/passwd", O_RDONLY));
  EXPECT_NOTCAPABLE(openat(etc_cap_ro, "../etc/passwd", O_RDONLY));
  EXPECT_NOTCAPABLE(openat(etc_cap_base, "../etc/passwd", O_RDONLY));

  fd = openat(etc, "passwd", O_RDONLY);
  EXPECT_OK(fd);

  // A file opened relative to a capability should itself be a capability.
  fd = openat(etc_cap_base, "passwd", O_RDONLY);
  EXPECT_OK(fd);
  EXPECT_OK(cap_getrights(fd, &rights));
  EXPECT_RIGHTS_IN(rights, baserights);
  close(fd);

  fd = openat(etc_cap_ro, "passwd", O_RDONLY);
  EXPECT_OK(fd);
  EXPECT_OK(cap_getrights(fd, &rights));
  EXPECT_RIGHTS_IN(rights, (CAP_READ|CAP_LOOKUP));
  close(fd);
}

TEST(Openat, Subdir) {
  // Create a couple of nested directories
  int rc = mkdir("/tmp/cap_topdir", 0755);
  EXPECT_OK(rc);
  if (rc < 0 && errno != EEXIST) return;
  rc = mkdir("/tmp/cap_topdir/cap_subdir", 0755);
  EXPECT_OK(rc);
  if (rc < 0 && errno != EEXIST) return;

  int dir_fd = open("/tmp/cap_topdir", O_RDONLY);
  EXPECT_OK(dir_fd);
  int cap_dir = cap_new(dir_fd, CAP_LOOKUP|CAP_READ);
  EXPECT_OK(cap_dir);

  // Check that we can't escape the top directory by the cunning
  // ruse of going via a subdirectory.
  EXPECT_NOTCAPABLE(openat(cap_dir, "cap_subdir/../../etc/passwd", O_RDONLY));

  pid_t child = fork();
  if (child == 0) {
    EXPECT_OK(cap_enter());  // Enter capability mode
    EXPECT_NOTCAPABLE(openat(cap_dir, "cap_subdir/../../etc/passwd", O_RDONLY));
    exit(HasFailure());
  }
  int status;
  EXPECT_EQ(child, waitpid(child, &status, 0));
  rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  EXPECT_EQ(0, rc);
  // Tidy up.
  rmdir("/tmp/cap_topdir/cap_subdir");
  rmdir("/tmp/cap_topdir");
}

#define SYMLINK_DIR "/tmp/cap_openat_symlink"
TEST(Openat, RelativeSymlink) {
  // Prepare a directory containing:
  //  -rw-rw-r--  normal
  //  lrwxrwxrwx  symlink.absolute_in -> /tmp/cap_openat_symlink/normal
  //  lrwxrwxrwx  symlink.absolute_out -> /etc/passwd
  //  lrwxrwxrwx  symlink.normal -> normal
  //  lrwxrwxrwx  symlink.relative_in -> ../../tmp/cap_openat_symlink/normal
  //  lrwxrwxrwx  symlink.relative_out -> ../../etc/passwd
  int rc = mkdir(SYMLINK_DIR, 0755);
  EXPECT_OK(rc);
  if (rc < 0 && errno != EEXIST) return;
  int dir_fd = open(SYMLINK_DIR, O_RDONLY);
  EXPECT_OK(dir_fd);
  int cap_dir = cap_new(dir_fd, CAP_LOOKUP|CAP_READ);
  EXPECT_OK(cap_dir);
  int normal = open(SYMLINK_DIR "/normal", O_CREAT|O_RDWR, 0644);
  EXPECT_OK(normal);
  const char *contents = "Hello world\n";
  EXPECT_OK(write(normal, contents, strlen(contents)));
  close(normal);

  EXPECT_OK(symlink(SYMLINK_DIR "/normal", SYMLINK_DIR "/symlink.absolute_in"));
  EXPECT_OK(symlink("/etc/passwd", SYMLINK_DIR "/symlink.absolute_out"));
  EXPECT_OK(symlink("normal", SYMLINK_DIR "/symlink.normal"));
  EXPECT_OK(symlink("../.." SYMLINK_DIR "/normal", SYMLINK_DIR "/symlink.relative_in"));
  EXPECT_OK(symlink("../../etc/passwd", SYMLINK_DIR "/symlink.relative_out"));

  // Any kind of symlink can be opened relative to an ordinary directory FD.
  EXPECT_OPEN_OK(openat(dir_fd, "symlink.normal", O_RDONLY));
  EXPECT_OPEN_OK(openat(dir_fd, "symlink.absolute_in", O_RDONLY));
  EXPECT_OPEN_OK(openat(dir_fd, "symlink.absolute_out", O_RDONLY));
  EXPECT_OPEN_OK(openat(dir_fd, "symlink.relative_in", O_RDONLY));
  EXPECT_OPEN_OK(openat(dir_fd, "symlink.relative_out", O_RDONLY));

  // Even when not in capability mode, should only be able to open symlinks that
  // stay within the directory.
  EXPECT_OPEN_OK(openat(cap_dir, "symlink.normal", O_RDONLY));
  EXPECT_NOTCAPABLE(openat(cap_dir, "symlink.absolute_in", O_RDONLY));
  EXPECT_NOTCAPABLE(openat(cap_dir, "symlink.absolute_out", O_RDONLY));
  EXPECT_NOTCAPABLE(openat(cap_dir, "symlink.relative_in", O_RDONLY));
  EXPECT_NOTCAPABLE(openat(cap_dir, "symlink.relative_out", O_RDONLY));

  int child = fork();
  if (child == 0) {
    // Child process: run the test in capability mode
    EXPECT_OK(cap_enter());

    // Only symlink within the directory can be opened relative to an ordinary directory FD.
    EXPECT_OPEN_OK(openat(dir_fd, "normal", O_RDONLY));
    EXPECT_OPEN_OK(openat(dir_fd, "symlink.normal", O_RDONLY));
    EXPECT_NOTCAPABLE(openat(dir_fd, "symlink.absolute_in", O_RDONLY));
    EXPECT_NOTCAPABLE(openat(dir_fd, "symlink.absolute_out", O_RDONLY));
    EXPECT_NOTCAPABLE(openat(dir_fd, "symlink.relative_in", O_RDONLY));
    EXPECT_NOTCAPABLE(openat(dir_fd, "symlink.relative_out", O_RDONLY));

    // Only symlink within the directory can be opened relative to an ordinary directory FD.
    EXPECT_OPEN_OK(openat(cap_dir, "normal", O_RDONLY));
    EXPECT_OPEN_OK(openat(cap_dir, "symlink.normal", O_RDONLY));
    EXPECT_NOTCAPABLE(openat(cap_dir, "symlink.absolute_in", O_RDONLY));
    EXPECT_NOTCAPABLE(openat(cap_dir, "symlink.absolute_out", O_RDONLY));
    EXPECT_NOTCAPABLE(openat(cap_dir, "symlink.relative_in", O_RDONLY));
    EXPECT_NOTCAPABLE(openat(cap_dir, "symlink.relative_out", O_RDONLY));
    exit(HasFailure());
  }
  int status;
  EXPECT_EQ(child, waitpid(child, &status, 0));
  rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  EXPECT_EQ(0, rc);

  // Tidy up
  unlink(SYMLINK_DIR "/symlink.absolute_in");
  unlink(SYMLINK_DIR "/symlink.absolute_out");
  unlink(SYMLINK_DIR "/symlink.normal");
  unlink(SYMLINK_DIR "/symlink.relative_in");
  unlink(SYMLINK_DIR "/symlink.relative_out");
  unlink(SYMLINK_DIR "/normal");
  rmdir(SYMLINK_DIR);
}
