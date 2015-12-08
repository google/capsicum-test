#include <stddef.h>

#include "testcasper.h"
#include <cap_random/cap_random.h>

class CasperRandomTest : public CasperTest {
 public:
  CasperRandomTest() : CasperTest("system.random") { }
};

TEST_F(CasperRandomTest, RandomBuf) {
  unsigned char buffer[256];
  memset(buffer, 0, sizeof(buffer));
  cap_random_buf(chan_, buffer, sizeof(buffer));
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
