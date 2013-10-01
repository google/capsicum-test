#include "gtest/gtest.h"

const char* g_argv_0;

int main(int argc, char* argv[]) {
  // We exec() ourselves in some tests; the argument indicates what the
  // expected result should be.
  if (argc == 2 && !strcmp(argv[1], "--pass")) {
    fprintf(stderr,"pid %d immediately returning 0\n", getpid());
    exit(0);
  }

  if (argc == 2 && !strcmp(argv[1], "--fail")) {
    fprintf(stderr,"pid %d immediately returning 0\n", getpid());
    exit(1);
  }

  ::testing::InitGoogleTest(&argc, argv);

  // Make argv[0] globally visible, for use in exec() tests.
  g_argv_0 = argv[0];

  return RUN_ALL_TESTS();
}
