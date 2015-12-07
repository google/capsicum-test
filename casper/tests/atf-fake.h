/* Fake up a translation from ATF to GoogleTest */

#include "gtest/gtest.h"
#define ATF_TEST_CASE_WITHOUT_HEAD(X) extern int dummy
#define ATF_TEST_CASE_BODY(X) TEST(ATF, X)
#define ATF_REQUIRE(X) ASSERT_TRUE((bool)(X))
#define ATF_REQUIRE_EQ(X, Y) ASSERT_EQ(X, Y)
#define ATF_FAIL(X) FAIL() << X
#define ATF_INIT_TEST_CASES(X) static void noop()
#define ATF_ADD_TEST_CASE(X, Y)
