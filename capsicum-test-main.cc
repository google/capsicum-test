#include <iostream>
#include "gtest/gtest.h"
#include "capsicum-test.h"

int main(int argc, char* argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  for (int ii = 1; ii < argc; ii++) {
    if (strcmp(argv[ii], "-v") == 0) {
      verbose = true;
    } else if (strcmp(argv[ii], "-t") == 0) {
      force_mt = true;
    } else if (strcmp(argv[ii], "-F") == 0) {
      force_nofork = true;
    }
  }
  int rc = RUN_ALL_TESTS();
  ShowSkippedTests(std::cerr);
  return rc;
}
