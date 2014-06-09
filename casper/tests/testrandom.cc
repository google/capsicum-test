#include <stddef.h>

#include <libcapsicum.h>
#include <libcapsicum_service.h>
#include <libcapsicum_random.h>

#include "gtest/gtest.h"

extern bool verbose;
extern const char *casper_sock;

class CasperRandomTest : public ::testing::Test {
 public:
  CasperRandomTest() : random_chan_(nullptr) {
    cap_channel_t *chan = cap_init_sock(casper_sock);
    EXPECT_NE(nullptr, chan) << "Failed to open socket " << casper_sock;
    if (!chan) return;
    random_chan_ = cap_service_open(chan, "system.random");
    EXPECT_NE(nullptr, random_chan_) << "Failed to open system.random service";
    cap_close(chan);
  }
  bool CheckSkip() {
    if (random_chan_ == nullptr) {
      fprintf(stderr, "Skipping test as system.random service unavailable\n");
      return true;
    } else {
      return false;
    }
  }
  ~CasperRandomTest() {
    if (random_chan_) cap_close(random_chan_);
  }
 protected:
  cap_channel_t *random_chan_;
};

TEST_F(CasperRandomTest, RandomBuf) {
  unsigned char buffer[256];
  memset(buffer, 0, sizeof(buffer));
  cap_random_buf(random_chan_, buffer, sizeof(buffer));
  bool seen_nonzero = false;
  if (verbose) fprintf(stderr, "Random data: ");
  for (size_t ii = 0; ii < sizeof(buffer); ii++) {
    if (verbose) fprintf(stderr, "%02x", buffer[ii]);
    if (buffer[ii] != 0) {
      seen_nonzero = true;
    }
  }
  if (verbose) fprintf(stderr, "\n");
  EXPECT_TRUE(seen_nonzero);
}
