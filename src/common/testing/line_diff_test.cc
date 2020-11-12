#include "src/common/testing/line_diff.h"

#include <gmock/gmock.h>  // IWYU pragma: export
#include <gtest/gtest.h>  // IWYU pragma: export

#include "src/common/base/base.h"

namespace pl {
namespace testing {

using ::testing::StrEq;

TEST(DiffingTest, CommonCases) {
  const std::string lhs =
      R"(
a
f
c
f
e)";
  const std::string rhs =
      R"(
a
b
c
e)";
  EXPECT_THAT(DiffLines(lhs, rhs), StrEq("  \n"
                                         R"(  a
l:f
r:b
  c
l:f
  e)"));
  EXPECT_THAT(DiffLines(lhs, rhs, DiffPolicy::kIgnoreBlankLines), StrEq(
                                                                      R"(  a
l:f
r:b
  c
l:f
  e)"));
}

TEST(DiffingTest, EmptyStrings) {
  EXPECT_THAT(DiffLines("", R"(a
b)"),
              StrEq(R"(l:
r:a
r:b)"));
  EXPECT_THAT(DiffLines("", R"(a
b)",
                        DiffPolicy::kIgnoreBlankLines),
              StrEq(R"(r:a
r:b)"));

  EXPECT_THAT(DiffLines(R"(a
b)",
                        ""),
              StrEq(R"(l:a
l:b
r:)"));
  EXPECT_THAT(DiffLines(R"(a
b)",
                        "", DiffPolicy::kIgnoreBlankLines),
              StrEq(R"(l:a
l:b)"));
}

}  // namespace testing
}  // namespace pl
