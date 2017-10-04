#include <fcntl.h>
#include <sys/stat.h>

#include "./capsicum-test.h"
#define RENAME_TEST_FILENAME        ".rename_test"
#define RENAMEAT_TEST_FILENAME      ".renameat_test"
#define RENAMEAT_TEST_DIR           ".renameat_testdir"

/*
added to test the renameat syscall for the case that
    - the "to" file already exists
    - the "to" file is specified by an absolute path
    - the "to" file descriptor is used

details at: https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=222258
*/

const char * create_tmp_src(const char* filename) {
    const char *src_path = TmpFile(filename);
    int src_fd = open(src_path, O_CREAT|O_RDWR, 0644);
    close(src_fd);
    return src_path;
}

TEST(Rename, rename_abs) {
    const char *src_path = create_tmp_src(RENAME_TEST_FILENAME);
    int ret = rename(src_path, src_path);
    EXPECT_OK(ret);
    unlink(src_path);
    return;
}

TEST(Rename, renameat_abs) {
    const char *src_path = create_tmp_src(RENAMEAT_TEST_FILENAME);
    const char *dir_path = TmpFile(RENAMEAT_TEST_DIR);

    EXPECT_OK(mkdir(dir_path, 0755));
    // random temporary directory descriptor
    int dir_fd = open(dir_path, O_DIRECTORY);

    int ret;
    ret = renameat(AT_FDCWD, src_path, AT_FDCWD, src_path);
    EXPECT_OK(ret);
    ret = renameat(AT_FDCWD, src_path, dir_fd, src_path);
    EXPECT_OK(ret);
    ret = renameat(dir_fd, src_path, AT_FDCWD, src_path);
    EXPECT_OK(ret);
    ret = renameat(dir_fd, src_path, dir_fd, src_path);
    EXPECT_OK(ret);

    close(dir_fd);
    unlink(src_path);
    return;
}
