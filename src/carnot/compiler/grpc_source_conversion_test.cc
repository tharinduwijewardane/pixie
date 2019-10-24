#include <gmock/gmock.h>
#include <google/protobuf/text_format.h>
#include <gtest/gtest.h>

#include <utility>
#include <vector>

#include <pypa/parser/parser.hh>

#include "src/carnot/compiler/grpc_source_conversion.h"
#include "src/carnot/compiler/test_utils.h"

namespace pl {
namespace carnot {
namespace compiler {
namespace distributed {

using testing::_;
using testing::ElementsAreArray;
using testing::UnorderedElementsAreArray;

class GRPCSourceConversionTest : public OperatorTests {};
TEST_F(GRPCSourceConversionTest, construction_test) {
  int64_t grpc_bridge_id = 123;
  std::string grpc_address = "1111";
  auto grpc_source_group = MakeGRPCSourceGroup(grpc_bridge_id, MakeTimeRelation());
  grpc_source_group->SetGRPCAddress(grpc_address);
  int64_t grpc_source_group_id = grpc_source_group->id();
  auto mem_sink = MakeMemSink(grpc_source_group, "out");

  auto mem_src1 = MakeMemSource(MakeTimeRelation());
  auto grpc_sink1 = MakeGRPCSink(mem_src1, grpc_bridge_id);
  grpc_sink1->SetDistributedID("agent-1");

  auto mem_src2 = MakeMemSource(MakeTimeRelation());
  auto grpc_sink2 = MakeGRPCSink(mem_src2, grpc_bridge_id);
  grpc_sink2->SetDistributedID("agent-2");

  EXPECT_OK(grpc_source_group->AddGRPCSink(grpc_sink1));
  EXPECT_OK(grpc_source_group->AddGRPCSink(grpc_sink2));

  std::vector<std::string> expected_physical_ids = {grpc_sink1->DistributedDestinationID(),
                                                    grpc_sink2->DistributedDestinationID()};

  // run the conversion rule.
  GRPCSourceGroupConversionRule rule;
  auto result = rule.Execute(graph.get());
  ASSERT_OK(result);
  bool does_change = result.ConsumeValueOrDie();
  EXPECT_TRUE(does_change);

  // Check to see that the group is no longer available
  EXPECT_FALSE(graph->HasNode(grpc_source_group_id));

  // Check to see that mem_sink has a new parent that is a union.
  ASSERT_EQ(mem_sink->parents().size(), 1UL);
  OperatorIR* mem_sink_parent = mem_sink->parents()[0];
  ASSERT_EQ(mem_sink_parent->type(), IRNodeType::kUnion) << mem_sink_parent->type_string();

  // Check to see that the union's parents are grpc_sources
  std::vector<std::string> actual_physical_ids;
  UnionIR* union_op = static_cast<UnionIR*>(mem_sink_parent);
  EXPECT_TRUE(union_op->IsRelationInit());
  EXPECT_TRUE(union_op->HasColumnMappings());
  for (auto* union_op_parent : union_op->parents()) {
    ASSERT_EQ(union_op_parent->type(), IRNodeType::kGRPCSource) << union_op_parent->type_string();
    auto grpc_source = static_cast<GRPCSourceIR*>(union_op_parent);
    actual_physical_ids.push_back(grpc_source->remote_source_id());
  }

  // Accumulate the GRPC source group ids and make sure they match the GRPC sink ones.
  EXPECT_THAT(actual_physical_ids, UnorderedElementsAreArray(expected_physical_ids));
}

// When making a single source, no need to have a union.
TEST_F(GRPCSourceConversionTest, construction_test_single_source) {
  int64_t grpc_bridge_id = 123;
  std::string grpc_address = "1111";
  auto grpc_source_group = MakeGRPCSourceGroup(grpc_bridge_id, MakeTimeRelation());
  grpc_source_group->SetGRPCAddress(grpc_address);
  int64_t grpc_source_group_id = grpc_source_group->id();
  auto mem_sink1 = MakeMemSink(grpc_source_group, "out");

  auto mem_src1 = MakeMemSource(MakeTimeRelation());
  auto grpc_sink1 = MakeGRPCSink(mem_src1, grpc_bridge_id);
  grpc_sink1->SetDistributedID("agent-1");

  EXPECT_OK(grpc_source_group->AddGRPCSink(grpc_sink1));

  // run the conversion rule.
  GRPCSourceGroupConversionRule rule;
  auto result = rule.Execute(graph.get());
  ASSERT_OK(result);
  bool does_change = result.ConsumeValueOrDie();
  EXPECT_TRUE(does_change);

  // Check to see that the group is no longer available
  EXPECT_FALSE(graph->HasNode(grpc_source_group_id));

  EXPECT_OK(grpc_source_group->AddGRPCSink(grpc_sink1));
  // Check to see that mem_sink1 has a new parent that is a union.
  ASSERT_EQ(mem_sink1->parents().size(), 1UL);
  OperatorIR* mem_sink1_parent = mem_sink1->parents()[0];
  ASSERT_EQ(mem_sink1_parent->type(), IRNodeType::kGRPCSource) << mem_sink1_parent->type_string();

  auto grpc_source1 = static_cast<GRPCSourceIR*>(mem_sink1_parent);
  EXPECT_EQ(grpc_source1->remote_source_id(), grpc_sink1->DistributedDestinationID());
}

TEST_F(GRPCSourceConversionTest, no_sinks_affiliated) {
  int64_t grpc_bridge_id = 123;
  std::string grpc_address = "1111";
  auto grpc_source_group = MakeGRPCSourceGroup(grpc_bridge_id, MakeTimeRelation());
  grpc_source_group->SetGRPCAddress(grpc_address);
  MakeMemSink(grpc_source_group, "out");

  // run the conversion rule.
  GRPCSourceGroupConversionRule rule;
  auto result = rule.Execute(graph.get());
  ASSERT_NOT_OK(result);
  EXPECT_THAT(
      result.status(),
      HasCompilerError("GRPCSourceGroup\\(id=[0-9]*\\) must be affiliated with remote sinks."));
}

TEST_F(GRPCSourceConversionTest, multiple_grpc_source_groups) {
  int64_t grpc_bridge_id1 = 123;
  int64_t grpc_bridge_id2 = 456;
  std::string grpc_address = "1111";
  auto grpc_source_group1 = MakeGRPCSourceGroup(grpc_bridge_id1, MakeTimeRelation());
  grpc_source_group1->SetGRPCAddress(grpc_address);
  int64_t grpc_source_group_id1 = grpc_source_group1->id();
  auto mem_sink1 = MakeMemSink(grpc_source_group1, "out");

  auto grpc_source_group2 = MakeGRPCSourceGroup(grpc_bridge_id2, MakeTimeRelation());
  grpc_source_group2->SetGRPCAddress(grpc_address);
  int64_t grpc_source_group_id2 = grpc_source_group2->id();
  auto mem_sink2 = MakeMemSink(grpc_source_group2, "out");

  auto mem_src1 = MakeMemSource(MakeTimeRelation());
  auto grpc_sink1 = MakeGRPCSink(mem_src1, grpc_bridge_id1);
  grpc_sink1->SetDistributedID("agent-1");

  auto mem_src2 = MakeMemSource(MakeTimeRelation());
  auto grpc_sink2 = MakeGRPCSink(mem_src2, grpc_bridge_id2);
  grpc_sink2->SetDistributedID("agent-2");

  EXPECT_OK(grpc_source_group1->AddGRPCSink(grpc_sink1));
  EXPECT_OK(grpc_source_group2->AddGRPCSink(grpc_sink2));

  std::vector<std::string> expected_physical_ids = {grpc_sink1->DistributedDestinationID(),
                                                    grpc_sink2->DistributedDestinationID()};

  // run the conversion rule.
  GRPCSourceGroupConversionRule rule;
  auto result = rule.Execute(graph.get());
  ASSERT_OK(result);
  bool does_change = result.ConsumeValueOrDie();
  EXPECT_TRUE(does_change);

  // Check to see that the group is no longer available
  EXPECT_FALSE(graph->HasNode(grpc_source_group_id1));
  EXPECT_FALSE(graph->HasNode(grpc_source_group_id2));

  // Check to see that mem_sink1 has a new parent that is a union.
  ASSERT_EQ(mem_sink1->parents().size(), 1UL);
  OperatorIR* mem_sink1_parent = mem_sink1->parents()[0];
  ASSERT_EQ(mem_sink1_parent->type(), IRNodeType::kGRPCSource) << mem_sink1_parent->type_string();

  auto grpc_source1 = static_cast<GRPCSourceIR*>(mem_sink1_parent);
  EXPECT_EQ(grpc_source1->remote_source_id(), grpc_sink1->DistributedDestinationID());

  // Check to see that mem_sink2 has a new parent that is a union.
  ASSERT_EQ(mem_sink2->parents().size(), 1UL);
  OperatorIR* mem_sink2_parent = mem_sink2->parents()[0];
  ASSERT_EQ(mem_sink2_parent->type(), IRNodeType::kGRPCSource) << mem_sink2_parent->type_string();

  auto grpc_source2 = static_cast<GRPCSourceIR*>(mem_sink2_parent);
  EXPECT_EQ(grpc_source2->remote_source_id(), grpc_sink2->DistributedDestinationID());
}

}  // namespace distributed
}  // namespace compiler
}  // namespace carnot
}  // namespace pl
