#ifndef TESTCASPER_H
#define TESTCASPER_H

#include <libcasper.h>
#include "gtest/gtest.h"

extern bool verbose;

class CasperTest : public ::testing::Test {
 public:
  explicit CasperTest(const char *service) : chan_(nullptr) {
    cap_channel_t *chan = cap_init();
    EXPECT_NE(nullptr, chan) << "Failed to cap_init()";
    if (!chan) return;
    chan_ = cap_service_open(chan, service);
    EXPECT_NE(nullptr, chan_) << "Failed to open " << service << " service";
    cap_close(chan);
  }
  bool CheckSkip() {
    if (chan_ == nullptr) {
      fprintf(stderr, "Skipping test as system.dns service unavailable\n");
      return true;
    } else {
      return false;
    }
  }
  ~CasperTest() {
    if (chan_) cap_close(chan_);
  }
 protected:
  cap_channel_t *chan_;
};

#endif
