#include "pjdlog.h"

#include <string>

#include "gtest/gtest.h"

extern bool verbose;

TEST(Pjdlog, Basic) {
  int count = 1;
  pjdlog_init(PJDLOG_MODE_STD);
  pjdlog_prefix_set("casper-test: ");
  pjdlog_info("Info level log %d", count++);
  pjdlog_notice("Notice level log %d", count++);
  pjdlog_fini();
}

TEST(Pjdlog, PrefixNest) {
  int count = 1;
  pjdlog_init(PJDLOG_MODE_STD);
  pjdlog_prefix_set("casper-test 0: ");
  pjdlog_info("Info level log %d", count++);
  pjdlog_prefix_push("nest1: ");
  pjdlog_notice("nest1 Notice level log %d", count++);
  pjdlog_prefix_push("nest2: ");
  pjdlog_notice("nest2 Notice level log %d", count++);
  pjdlog_prefix_pop();
  pjdlog_notice("nest1 Notice level log %d", count++);
  pjdlog_prefix_pop();
  pjdlog_notice("default Notice level log %d", count++);
  pjdlog_fini();
}

TEST(PjdlogDeathTest, IncorrectPrefixNest) {
  ::testing::FLAGS_gtest_death_test_style = "threadsafe";
  int count = 1;
  pjdlog_init(PJDLOG_MODE_STD);
  pjdlog_prefix_set("casper-test 0: ");  // Base
  pjdlog_info("Info level log %d", count++);
  pjdlog_prefix_push("nest1: ");  // Level 1
  pjdlog_notice("Notice level log %d", count++);
  pjdlog_prefix_pop();  // Back to base
  pjdlog_notice("Notice level log %d", count++);

  EXPECT_DEATH(pjdlog_prefix_pop(), "Assertion");
  pjdlog_fini();
}

TEST(PjdlogDeathTest, Abort) {
  ::testing::FLAGS_gtest_death_test_style = "threadsafe";
  pjdlog_init(PJDLOG_MODE_STD);
  EXPECT_DEATH(PJDLOG_ABORT("Aborting test"), "Aborting test");
  pjdlog_fini();
}

TEST(Pjdlog, Syslog) {
  pjdlog_init(PJDLOG_MODE_SYSLOG);
  pjdlog_prefix_set("casper-test: ");
  pjdlog_info("Please ignore, test log to syslog");
  pjdlog_fini();
}
