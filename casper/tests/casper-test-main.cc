#include "gtest/gtest.h"

bool verbose = false;
const char *casper_sock = "/var/run/casper";

int main(int argc, char* argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  for (int ii = 1; ii < argc; ii++) {
    if (strcmp(argv[ii], "-v") == 0) {
      verbose = true;
    } else if (strcmp(argv[ii], "-S") == 0 && (ii+1) < argc) {
      casper_sock = argv[ii+1];
    }
  }
  int rc = RUN_ALL_TESTS();
  return rc;
}

