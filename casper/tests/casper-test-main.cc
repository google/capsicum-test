#include "gtest/gtest.h"

bool verbose = false;

int main(int argc, char* argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  for (int ii = 1; ii < argc; ii++) {
    if (strcmp(argv[ii], "-v") == 0) {
      verbose = true;
    }
  }
  int rc = RUN_ALL_TESTS();
  return rc;
}

