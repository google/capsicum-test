#include <iostream>
#include "gtest/gtest.h"
#include "capsicum-test.h"

int main(int argc, char* argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  int rc = RUN_ALL_TESTS();
  ShowSkippedTests(std::cerr);
  return rc;
}
