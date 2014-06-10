#include "nv.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <string>

#include "gtest/gtest.h"

extern bool verbose;
static nvlist_t *nvnull = NULL;

// Param indicates whether names are case-sensitive
class NVListTest : public ::testing::TestWithParam<bool> {
};

TEST_P(NVListTest, Basic) {
  bool case_sensitive = GetParam();
  nvlist_t *list = nvlist_create(case_sensitive ? 0 : NV_FLAG_IGNORE_CASE);
  EXPECT_TRUE(nvlist_empty(list));

  EXPECT_EQ(ENOMEM, nvlist_error(NULL));
  EXPECT_EQ(0, nvlist_error(list));

  nvlist_t *list2 = nvlist_clone(list);
  EXPECT_NE(nvnull, list2);
  EXPECT_TRUE(nvlist_empty(list2));

  EXPECT_FALSE(nvlist_exists(list, "null_field"));
  EXPECT_FALSE(nvlist_exists(list, "bool_field"));
  EXPECT_FALSE(nvlist_exists(list2, "null_field"));
  EXPECT_FALSE(nvlist_exists(list2, "bool_field"));

  // Add a null and a bool
  nvlist_add_null(list, "null_field");
  nvlist_add_bool(list, "bool_field", true);

  EXPECT_TRUE(nvlist_exists(list, "null_field"));
  EXPECT_EQ(!case_sensitive, nvlist_exists(list, "NULL_FIELD"));
  EXPECT_TRUE(nvlist_exists_null(list, "null_field"));
  EXPECT_FALSE(nvlist_exists_bool(list, "null_field"));
  EXPECT_TRUE(nvlist_exists_type(list, "null_field", NV_TYPE_NULL));
  EXPECT_FALSE(nvlist_exists_type(list, "null_field", NV_TYPE_BOOL));

  EXPECT_TRUE(nvlist_exists(list, "bool_field"));
  EXPECT_TRUE(nvlist_exists_bool(list, "bool_field"));
  EXPECT_FALSE(nvlist_exists_null(list, "bool_field"));
  EXPECT_TRUE(nvlist_exists_type(list, "bool_field", NV_TYPE_BOOL));
  EXPECT_FALSE(nvlist_exists_type(list, "bool_field", NV_TYPE_NULL));
  EXPECT_EQ(true, nvlist_get_bool(list, "bool_field"));

  // No effect on the previously cloned list
  EXPECT_FALSE(nvlist_exists(list2, "null_field"));
  EXPECT_FALSE(nvlist_exists_null(list2, "null_field"));
  EXPECT_FALSE(nvlist_exists_bool(list2, "null_field"));
  EXPECT_FALSE(nvlist_exists_type(list2, "null_field", NV_TYPE_NULL));
  EXPECT_FALSE(nvlist_exists_type(list2, "null_field", NV_TYPE_BOOL));

  EXPECT_FALSE(nvlist_exists(list2, "bool_field"));
  EXPECT_FALSE(nvlist_exists_bool(list2, "bool_field"));
  EXPECT_FALSE(nvlist_exists_null(list2, "bool_field"));
  EXPECT_FALSE(nvlist_exists_type(list2, "bool_field", NV_TYPE_BOOL));
  EXPECT_FALSE(nvlist_exists_type(list2, "bool_field", NV_TYPE_NULL));

  // String values.
  nvlist_add_string(list2, "string_field1", "value 1");
  nvlist_add_stringf(list2, "string_field2", "format int %d and string '%s'", 13, "foo");
  EXPECT_EQ("value 1", std::string(nvlist_get_string(list2, "string_field1")));
  EXPECT_EQ("format int 13 and string 'foo'", std::string(nvlist_get_string(list2, "string_field2")));

  // Dump to file.
  int fd = open("/tmp/nvtest_dump.txt", O_RDWR | O_CREAT | O_TRUNC, 0644);
  nvlist_dump(list, fd);
  struct stat info;
  EXPECT_EQ(0, fstat(fd, &info));
  EXPECT_LT(0, info.st_size);
  close(fd);
  unlink("/tmp/nvtest_dump.txt");

  // Check packed sizes.
  size_t size = nvlist_size(list);
  size_t size2;
  void *data = nvlist_pack(list, &size2);
  EXPECT_EQ(size, size2);

  nvlist_t *list3 = nvlist_unpack(data, size2);
  free(data);

  // Unpacked data should have the same content.
  EXPECT_TRUE(nvlist_exists(list, "null_field"));
  EXPECT_TRUE(nvlist_exists_null(list, "null_field"));
  EXPECT_TRUE(nvlist_exists(list, "bool_field"));
  EXPECT_TRUE(nvlist_exists_bool(list, "bool_field"));
  EXPECT_EQ(true, nvlist_get_bool(list, "bool_field"));

  // Iterate over name/value pairs.
  int count = 0;
  void *cookie = NULL;
  int ntype;
  const char *name;
  while (true) {
    name = nvlist_next(list, &ntype, &cookie);
    if (!name) break;
    count++;
    EXPECT_TRUE(ntype == NV_TYPE_NULL || ntype == NV_TYPE_BOOL);
  }
  EXPECT_EQ(2, count);

  // Take string values.
  char *value = nvlist_take_string(list2, "string_field1");
  EXPECT_EQ("value 1", std::string(value));
  free(value);
  EXPECT_FALSE(nvlist_exists_string(list2, "string_field1"));

  // Free name/values.
  nvlist_free_string(list2, "string_field2");
  EXPECT_FALSE(nvlist_exists_string(list2, "string_field2"));
  nvlist_free_bool(list, "bool_field");
  EXPECT_FALSE(nvlist_exists_type(list, "bool_field", NV_TYPE_BOOL));

  // Cleanup
  nvlist_destroy(list);
  nvlist_destroy(list2);
  nvlist_destroy(list3);
}
INSTANTIATE_TEST_CASE_P(CaseSensitive, NVListTest, ::testing::Bool());

TEST(NVList, SocketSend) {
  int fds[2];
  EXPECT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  int fd = open("/tmp/nvtest_xfer", O_RDWR | O_CREAT | O_TRUNC, 0644);
  struct stat info;
  EXPECT_EQ(0, fstat(fd, &info));
  ino_t inode = info.st_ino;

  pid_t child = fork();
  if (child == 0) {
    // Child: wait to receive an nvlist.
    nvlist_t *list2 = nvlist_recv(fds[0]);
    if (verbose) {
      fprintf(stderr, "child: received nvlist:\n");
      nvlist_dump(list2, fileno(stderr));
    }
    EXPECT_TRUE(nvlist_exists_string(list2, "field1"));
    EXPECT_EQ("value1", std::string(nvlist_get_string(list2, "field1")));
    EXPECT_TRUE(nvlist_exists_number(list2, "field2"));
    EXPECT_EQ(42, nvlist_get_number(list2, "field2"));
    EXPECT_TRUE(nvlist_exists_binary(list2, "field3"));
    EXPECT_TRUE(nvlist_exists_descriptor(list2, "field4"));
    int fd2 = nvlist_get_descriptor(list2, "field4");
    EXPECT_EQ(0, fstat(fd2, &info));
    EXPECT_EQ(inode, info.st_ino);
    nvlist_destroy(list2);
    exit(HasFailure());
  }

  // Build an nvlist.
  nvlist_t *list = nvlist_create(0);
  nvlist_add_string(list, "field1", "value1");
  nvlist_add_number(list, "field2", 42);
  const unsigned char data[5] = {0x00, 0x01, 0x02, 0x03, 0x04};
  nvlist_add_binary(list, "field3", data, sizeof(data));
  nvlist_add_descriptor(list, "field4", fd);

  // Send it down the socket.
  EXPECT_EQ(0, nvlist_send(fds[1], list));

  // Wait for the child.
  int status;
  EXPECT_EQ(child, waitpid(child, &status, 0));
  EXPECT_TRUE(WIFEXITED(status)) << " status " << status;
  EXPECT_EQ(0, WEXITSTATUS(status));

  close(fd);
  nvlist_destroy(list);
  close(fds[1]);
  close(fds[0]);
  unlink("/tmp/nvtest_xfer");
}

TEST(NVList, SocketXfer) {
  int fds[2];
  EXPECT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

  pid_t child = fork();
  if (child == 0) {
    // Child: open a couple of files then wait to receive an nvlist.
    int fd = open("/etc/passwd", O_RDONLY);
    int fd2 = open("/etc/passwd", O_RDONLY);
    EXPECT_LE(0, fd);
    nvlist_t *list2 = nvlist_recv(fds[0]);
    if (verbose) {
      fprintf(stderr, "child: received nvlist:\n");
      nvlist_dump(list2, fileno(stderr));
    }

    // Respond with the fd.
    nvlist_t *rsp = nvlist_create(0);
    nvlist_move_descriptor(rsp, "rspfd", fd);
    nvlist_move_descriptor(rsp, "rspfd2", fd2);
    nvlist_add_number(rsp, "rc", 0);
    (void)nvlist_send(fds[0], rsp);
    nvlist_destroy(rsp);
    exit(HasFailure());
  }

  // Build an nvlist.
  nvlist_t *list = nvlist_create(0);
  nvlist_add_number(list, "field1", 123);
  nvlist_add_number(list, "field2", 42);

  // Send/recv it via the socket.
  list = nvlist_xfer(fds[1], list);
  EXPECT_NE(nullptr, list);
  if (list) {
    EXPECT_TRUE(nvlist_exists_number(list, "rc"));
    EXPECT_EQ(0, nvlist_get_number(list, "rc"));
    EXPECT_TRUE(nvlist_exists_descriptor(list, "rspfd"));
    int fd = nvlist_take_descriptor(list, "rspfd");
    EXPECT_LT(0, fd);
    EXPECT_TRUE(nvlist_exists_descriptor(list, "rspfd2"));
    int fd2 = nvlist_take_descriptor(list, "rspfd2");
    EXPECT_LT(0, fd2);
    close(fd);
  }

  // Wait for the child to terminate.
  int status;
  EXPECT_EQ(child, waitpid(child, &status, 0));
  EXPECT_TRUE(WIFEXITED(status)) << " status " << status;
  EXPECT_EQ(0, WEXITSTATUS(status));

  nvlist_destroy(list);
  close(fds[1]);
  close(fds[0]);
}

