#include <benchmark/benchmark.h>

#include "src/carnot/compiler/logical_planner/logical_planner.h"
#include "src/carnot/compiler/logical_planner/test_utils.h"
#include "src/carnot/udf_exporter/udf_exporter.h"
#include "src/common/base/test_utils.h"
#include "src/common/perf/perf.h"

namespace pl {
namespace carnot {
namespace compiler {
namespace logical_planner {

// NOLINTNEXTLINE : runtime/references.
void BM_Query(benchmark::State& state) {
  auto info = udfexporter::ExportUDFInfo().ConsumeValueOrDie()->info_pb();
  auto planner = LogicalPlanner::Create(info).ConsumeValueOrDie();
  auto planner_state =
      testutils::CreateTwoAgentsOneKelvinPlannerState(testutils::kHttpEventsSchema);
  plannerpb::QueryRequest query_request;
  query_request.set_query_str(testutils::kHttpRequestStats);
  for (auto _ : state) {
    auto plan_or_s = planner->Plan(planner_state, query_request);
    EXPECT_OK(plan_or_s);
  }
}

BENCHMARK(BM_Query);

}  // namespace logical_planner
}  // namespace compiler
}  // namespace carnot
}  // namespace pl
