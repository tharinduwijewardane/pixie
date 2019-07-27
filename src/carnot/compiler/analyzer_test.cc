#include <gmock/gmock.h>
#include <google/protobuf/text_format.h>
#include <gtest/gtest.h>

#include <unordered_map>
#include <utility>
#include <vector>

#include <pypa/parser/parser.hh>

#include "src/carnot/compiler/analyzer.h"
#include "src/carnot/compiler/compiler.h"
#include "src/carnot/compiler/compiler_state.h"
#include "src/carnot/compiler/test_utils.h"

namespace pl {
namespace carnot {
namespace compiler {

using testing::_;

const char* kExpectedUDFInfo = R"(
scalar_udfs {
  name: "pl.divide"
  exec_arg_types: FLOAT64
  exec_arg_types: FLOAT64
  return_type:FLOAT64
}
scalar_udfs {
  name: "pl.add"
  exec_arg_types: FLOAT64
  exec_arg_types: FLOAT64
  return_type:  FLOAT64
}
scalar_udfs {
  name: "pl.equal"
  exec_arg_types: STRING
  exec_arg_types: STRING
  return_type: BOOLEAN
}
scalar_udfs {
  name: "pl.multiply"
  exec_arg_types: FLOAT64
  exec_arg_types: FLOAT64
  return_type:  FLOAT64
}
scalar_udfs {
  name: "pl.subtract"
  exec_arg_types: FLOAT64
  exec_arg_types: FLOAT64
  return_type:  FLOAT64
}
scalar_udfs {
  name: "pl.upid_to_service_id"
  exec_arg_types: UINT128
  return_type: STRING
}
scalar_udfs {
  name: "pl.upid_to_service_name"
  exec_arg_types: UINT128
  return_type: STRING
}
scalar_udfs {
  name: "pl.service_id_to_service_name"
  exec_arg_types: STRING
  return_type: STRING
}
udas {
  name: "pl.count"
  update_arg_types: FLOAT64
  finalize_type:  INT64
}
udas {
  name: "pl.count"
  update_arg_types: INT64
  finalize_type:  INT64
}
udas {
  name: "pl.count"
  update_arg_types: BOOLEAN
  finalize_type:  INT64
}
udas {
  name: "pl.count"
  update_arg_types: STRING
  finalize_type:  INT64
}
udas {
  name: "pl.mean"
  update_arg_types: FLOAT64
  finalize_type:  FLOAT64
}
)";

class AnalyzerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Test::SetUp();
    relation_map_ = std::make_unique<RelationMap>();

    registry_info_ = std::make_shared<RegistryInfo>();
    udfspb::UDFInfo info_pb;
    google::protobuf::TextFormat::MergeFromString(kExpectedUDFInfo, &info_pb);
    EXPECT_OK(registry_info_->Init(info_pb));
    table_store::schema::Relation cpu_relation;
    relation_map_ = std::make_unique<RelationMap>();
    cpu_relation.AddColumn(types::FLOAT64, "cpu0");
    cpu_relation.AddColumn(types::FLOAT64, "cpu1");
    cpu_relation.AddColumn(types::FLOAT64, "cpu2");
    cpu_relation.AddColumn(types::UINT128, MetadataProperty::kUniquePIDColumn);
    relation_map_->emplace("cpu", cpu_relation);

    table_store::schema::Relation non_float_relation;
    non_float_relation.AddColumn(types::INT64, "int_col");
    non_float_relation.AddColumn(types::FLOAT64, "float_col");
    non_float_relation.AddColumn(types::STRING, "string_col");
    non_float_relation.AddColumn(types::BOOLEAN, "bool_col");
    relation_map_->emplace("non_float_table", non_float_relation);
    compiler_state_ =
        std::make_unique<CompilerState>(std::move(relation_map_), registry_info_.get(), time_now);
  }

  StatusOr<std::shared_ptr<IR>> CompileGraph(const std::string& query) {
    auto result = ParseQuery(query);
    PL_RETURN_IF_ERROR(result);
    // just a quick test to find issues.
    if (!result.ValueOrDie()->GetSinks().ok()) {
      return error::InvalidArgument("IR Doesn't have sink");
    }
    return result;
  }
  Status HandleRelation(std::shared_ptr<IR> ir_graph) {
    PL_ASSIGN_OR_RETURN(std::unique_ptr<Analyzer> analyzer,
                        Analyzer::Create(compiler_state_.get()));
    return analyzer->Execute(ir_graph.get());
  }
  bool RelationEquality(const table_store::schema::Relation& r1,
                        const table_store::schema::Relation& r2) {
    std::vector<std::string> r1_names;
    std::vector<std::string> r2_names;
    std::vector<types::DataType> r1_types;
    std::vector<types::DataType> r2_types;
    if (r1.NumColumns() >= r2.NumColumns()) {
      r1_names = r1.col_names();
      r1_types = r1.col_types();
      r2_names = r2.col_names();
      r2_types = r2.col_types();
    } else {
      r1_names = r2.col_names();
      r1_types = r2.col_types();
      r2_names = r1.col_names();
      r2_types = r1.col_types();
    }
    for (size_t i = 0; i < r1_names.size(); i++) {
      std::string col1 = r1_names[i];
      auto type1 = r1_types[i];
      auto r2_iter = std::find(r2_names.begin(), r2_names.end(), col1);
      // if we can't find name in the second relation, then
      if (r2_iter == r2_names.end()) {
        return false;
      }
      int64_t r2_idx = std::distance(r2_names.begin(), r2_iter);
      if (r2_types[r2_idx] != type1) {
        return false;
      }
    }
    return true;
  }

  /**
   * @brief Finds the specified type in the graph and returns the node.
   *
   *
   * @param ir_graph
   * @param type
   * @return StatusOr<IRNode*> IRNode of type, otherwise returns an error.
   */
  StatusOr<IRNode*> FindNodeType(std::shared_ptr<IR> ir_graph, IRNodeType type) {
    for (auto& i : ir_graph->dag().TopologicalSort()) {
      auto node = ir_graph->Get(i);
      if (node->type() == type) {
        return node;
      }
    }
    return error::NotFound("Couldn't find node of type $0 in ir_graph.",
                           kIRNodeStrings[static_cast<int64_t>(type)]);
  }

  std::shared_ptr<RegistryInfo> registry_info_;
  std::unique_ptr<RelationMap> relation_map_;
  std::unique_ptr<CompilerState> compiler_state_;
  int64_t time_now = 1552607213931245000;
};

TEST_F(AnalyzerTest, test_utils) {
  table_store::schema::Relation cpu2_relation;
  cpu2_relation.AddColumn(types::FLOAT64, "cpu0");
  cpu2_relation.AddColumn(types::FLOAT64, "cpu1");
  EXPECT_FALSE(RelationEquality((*compiler_state_->relation_map())["cpu"], cpu2_relation));
  EXPECT_TRUE(RelationEquality((*compiler_state_->relation_map())["cpu"],
                               (*compiler_state_->relation_map())["cpu"]));
}

TEST_F(AnalyzerTest, no_special_relation) {
  std::string from_expr = "From(table='cpu', select=['cpu0', 'cpu1']).Result(name='cpu')";
  auto ir_graph_status = CompileGraph(from_expr);
  ASSERT_OK(ir_graph_status);
  // now pass into the relation handler.
  auto handle_status = HandleRelation(ir_graph_status.ConsumeValueOrDie());
  EXPECT_OK(handle_status);
  VLOG(1) << handle_status.status().ToString();

  // check the connection of ig
  std::string from_range_expr =
      "From(table='cpu', select=['cpu0']).Range(start=0,stop=10).Result(name='cpu_out')";
  ir_graph_status = CompileGraph(from_expr);
  ASSERT_OK(ir_graph_status);
  // now pass into the relation handler.
  handle_status = HandleRelation(ir_graph_status.ConsumeValueOrDie());
  EXPECT_OK(handle_status);
  VLOG(1) << handle_status.status().ToString();
}

TEST_F(AnalyzerTest, assign_functionality) {
  std::string assign_and_use =
      absl::StrJoin({"queryDF = From(table = 'cpu', select = [ 'cpu0', 'cpu1' ])",
                     "queryDF.Range(start=0,stop=10).Result(name='cpu_out')"},
                    "\n");

  auto ir_graph_status = CompileGraph(assign_and_use);
  ASSERT_OK(ir_graph_status);
  // now pass into the relation handler.
  auto handle_status = HandleRelation(ir_graph_status.ConsumeValueOrDie());
  EXPECT_OK(handle_status);
  VLOG(1) << handle_status.status().ToString();
}

// Map Tests
TEST_F(AnalyzerTest, single_col_map) {
  std::string single_col_map_sum =
      absl::StrJoin({"queryDF = From(table='cpu', select=['cpu0', 'cpu1']).Range(start=0,stop=10)",
                     "mapDF = queryDF.Map(fn=lambda r : {'sum' : r.cpu0 + r.cpu1})",
                     "mapDF.Result(name='cpu_out')"},
                    "\n");
  auto ir_graph_status = CompileGraph(single_col_map_sum);
  ASSERT_OK(ir_graph_status);
  // now pass into the relation handler.
  auto handle_status = HandleRelation(ir_graph_status.ConsumeValueOrDie());
  EXPECT_OK(handle_status);
  VLOG(1) << handle_status.status().ToString();

  std::string single_col_div_map_query =
      absl::StrJoin({"queryDF = From(table='cpu', select=['cpu0', 'cpu1']).Range(start=0,stop=10)",
                     "mapDF = queryDF.Map(fn=lambda r : {'sum' : pl.divide(r.cpu0,r.cpu1)})",
                     "mapDF.Result(name='cpu_out')"},
                    "\n");
  ir_graph_status = CompileGraph(single_col_div_map_query);
  ASSERT_OK(ir_graph_status);
  // now pass into the relation handler.
  handle_status = HandleRelation(ir_graph_status.ConsumeValueOrDie());
  EXPECT_OK(handle_status);
  VLOG(1) << handle_status.status().ToString();
}

TEST_F(AnalyzerTest, multi_col_map) {
  std::string multi_col = absl::StrJoin(
      {
          "queryDF = From(table='cpu', select=['cpu0', 'cpu1', 'cpu2']).Range(start=0,stop=10)",
          "mapDF = queryDF.Map(fn=lambda r : {'sum' : r.cpu0 + r.cpu1, 'copy' : r.cpu2})",
          "mapDF.Result(name='cpu_out')",
      },
      "\n");
  auto ir_graph_status = CompileGraph(multi_col);
  ASSERT_OK(ir_graph_status);
  // now pass into the relation handler.
  auto handle_status = HandleRelation(ir_graph_status.ConsumeValueOrDie());
  EXPECT_OK(handle_status);
  VLOG(1) << handle_status.status().ToString();
}

TEST_F(AnalyzerTest, bin_op_test) {
  std::string single_col_map_sum =
      absl::StrJoin({"queryDF = From(table='cpu', select=['cpu0', 'cpu1']).Range(start=0,stop=10)",
                     "mapDF = queryDF.Map(fn=lambda r : {'sum' : r.cpu0 + r.cpu1})",
                     "mapDF.Result(name='cpu_out')"},
                    "\n");
  auto ir_graph_status = CompileGraph(single_col_map_sum);
  ASSERT_OK(ir_graph_status);
  // now pass into the relation handler.
  auto handle_status = HandleRelation(ir_graph_status.ConsumeValueOrDie());
  EXPECT_OK(handle_status);
  VLOG(1) << handle_status.status().ToString();

  std::string single_col_map_sub =
      absl::StrJoin({"queryDF = From(table='cpu', select=['cpu0', 'cpu1']).Range(start=0,stop=10)",
                     "mapDF = queryDF.Map(fn=lambda r : {'sub' : r.cpu0 - r.cpu1})",
                     "mapDF.Result(name='cpu_out')"},
                    "\n");
  ir_graph_status = CompileGraph(single_col_map_sub);
  ASSERT_OK(ir_graph_status);
  // now pass into the relation handler.
  handle_status = HandleRelation(ir_graph_status.ConsumeValueOrDie());
  EXPECT_OK(handle_status);
  VLOG(1) << handle_status.status().ToString();

  std::string single_col_map_product =
      absl::StrJoin({"queryDF = From(table='cpu', select=['cpu0', 'cpu1']).Range(start=0,stop=10)",
                     "mapDF = queryDF.Map(fn=lambda r : {'product' : r.cpu0 * r.cpu1})",
                     "mapDF.Result(name='cpu_out')"},
                    "\n");
  ir_graph_status = CompileGraph(single_col_map_product);
  ASSERT_OK(ir_graph_status);
  // now pass into the relation handler.
  handle_status = HandleRelation(ir_graph_status.ConsumeValueOrDie());
  EXPECT_OK(handle_status);
  VLOG(1) << handle_status.status().ToString();

  std::string single_col_map_quotient =
      absl::StrJoin({"queryDF = From(table='cpu', select=['cpu0', 'cpu1']).Range(start=0,stop=10)",
                     "mapDF = queryDF.Map(fn=lambda r : {'quotient' : r.cpu0 / r.cpu1})",
                     "mapDF.Result(name='cpu_out')"},
                    "\n");
  ir_graph_status = CompileGraph(single_col_map_quotient);
  ASSERT_OK(ir_graph_status);
  // now pass into the relation handler.
  handle_status = HandleRelation(ir_graph_status.ConsumeValueOrDie());
  EXPECT_OK(handle_status);
  VLOG(1) << handle_status.status().ToString();
}

TEST_F(AnalyzerTest, single_col_agg) {
  std::string single_col_agg =
      absl::StrJoin({"queryDF = From(table='cpu', select=['cpu0', 'cpu1']).Range(start=0,stop=10)",
                     "aggDF = queryDF.Agg(by=lambda r : r.cpu0, fn=lambda r : {'cpu_count' : "
                     "pl.count(r.cpu1)}).Result(name='cpu_out')"},
                    "\n");
  auto ir_graph_status = CompileGraph(single_col_agg);
  ASSERT_OK(ir_graph_status);
  // now pass into the relation handler.
  auto handle_status = HandleRelation(ir_graph_status.ConsumeValueOrDie());
  EXPECT_OK(handle_status);
  VLOG(1) << handle_status.status().ToString();
  std::string multi_output_col_agg =
      absl::StrJoin({"queryDF = From(table='cpu', select=['cpu0','cpu1']).Range(start=0,stop=10)",
                     "aggDF = queryDF.Agg(by=lambda r : r.cpu0, fn=lambda r : {'cpu_count': "
                     "pl.count(r.cpu1), 'cpu_mean' : pl.mean(r.cpu1)}).Result(name='cpu_out')"},
                    "\n");
  ir_graph_status = CompileGraph(multi_output_col_agg);
  ASSERT_OK(ir_graph_status);
  // now pass into the relation handler.
  handle_status = HandleRelation(ir_graph_status.ConsumeValueOrDie());
  EXPECT_OK(handle_status);
  VLOG(1) << handle_status.status().ToString();
}

// Make sure the relations match the expected values.
TEST_F(AnalyzerTest, test_relation_results) {
  // operators don't use generated columns, are just chained.
  std::string chain_operators = absl::StrJoin(
      {"queryDF = From(table='cpu', select=['upid', 'cpu0', 'cpu1', "
       "'cpu2']).Range(start=0,stop=10)",
       "mapDF = queryDF.Map(fn=lambda r : {'cpu0' : r.cpu0, 'cpu1' : r.cpu1, 'cpu_sum' : "
       "r.cpu0+r.cpu1})",
       "aggDF = mapDF.Agg(by=lambda r : r.cpu0, fn=lambda r : {'cpu_count' : "
       "pl.count(r.cpu1), 'cpu_mean' : pl.mean(r.cpu1)}).Result(name='cpu_out')"},
      "\n");
  auto ir_graph_status = CompileGraph(chain_operators);
  auto ir_graph = ir_graph_status.ConsumeValueOrDie();
  auto handle_status = HandleRelation(ir_graph);
  EXPECT_OK(handle_status);

  // Memory Source should copy the source relation.
  auto source_node_status = FindNodeType(ir_graph, IRNodeType::kMemorySource);
  EXPECT_OK(source_node_status);
  auto source_node = static_cast<MemorySourceIR*>(source_node_status.ConsumeValueOrDie());
  EXPECT_TRUE(RelationEquality(source_node->relation(), (*compiler_state_->relation_map())["cpu"]));
  auto mem_node_status = FindNodeType(ir_graph, IRNodeType::kMemorySink);

  // Map relation should be contain cpu0, cpu1, and cpu_sum.
  auto map_node_status = FindNodeType(ir_graph, IRNodeType::kMap);
  EXPECT_OK(map_node_status);
  auto map_node = static_cast<MapIR*>(map_node_status.ConsumeValueOrDie());
  auto test_map_relation_s =
      (*compiler_state_->relation_map())["cpu"].MakeSubRelation({"cpu0", "cpu1"});
  EXPECT_OK(test_map_relation_s);
  table_store::schema::Relation test_map_relation = test_map_relation_s.ConsumeValueOrDie();
  test_map_relation.AddColumn(types::FLOAT64, "cpu_sum");
  EXPECT_TRUE(RelationEquality(map_node->relation(), test_map_relation));

  // Agg should be a new relation with one column.
  auto agg_node_status = FindNodeType(ir_graph, IRNodeType::kBlockingAgg);
  EXPECT_OK(agg_node_status);
  auto agg_node = static_cast<BlockingAggIR*>(agg_node_status.ConsumeValueOrDie());
  table_store::schema::Relation test_agg_relation;
  test_agg_relation.AddColumn(types::INT64, "cpu_count");
  test_agg_relation.AddColumn(types::FLOAT64, "cpu_mean");
  test_agg_relation.AddColumn(types::FLOAT64, "cpu0");
  EXPECT_TRUE(RelationEquality(agg_node->relation(), test_agg_relation));

  // Sink should have the same relation as before and be equivalent to its parent.
  auto sink_node_status = FindNodeType(ir_graph, IRNodeType::kMemorySink);
  EXPECT_OK(sink_node_status);
  auto sink_node = static_cast<MemorySinkIR*>(sink_node_status.ConsumeValueOrDie());
  EXPECT_TRUE(RelationEquality(sink_node->relation(), test_agg_relation));
  EXPECT_TRUE(RelationEquality(sink_node->relation(), sink_node->parent()->relation()));
}  // namespace compiler

// Make sure the compiler exits when calling columns that aren't explicitly called.
TEST_F(AnalyzerTest, test_relation_fails) {
  // operators don't use generated columns, are just chained.
  std::string chain_operators = absl::StrJoin(
      {"queryDF = From(table='cpu', select=['cpu0', 'cpu1', 'cpu2']).Range(start=0,stop=10)",
       "mapDF = queryDF.Map(fn=lambda r : {'cpu_sum' : r.cpu0+r.cpu1})",
       "aggDF = mapDF.Agg(by=lambda r : r.cpu0, fn=lambda r : {'cpu_count' : "
       "pl.count(r.cpu1), 'cpu_mean' : pl.mean(r.cpu1)}).Result(name='cpu_out')"},
      "\n");
  auto ir_graph_status = CompileGraph(chain_operators);
  auto ir_graph = ir_graph_status.ConsumeValueOrDie();

  // This query assumes implicit copying of Input relation into Map. The relation handler should
  // fail.
  auto handle_status = HandleRelation(ir_graph);
  VLOG(1) << handle_status.ToString();
  EXPECT_FALSE(handle_status.ok());

  // Map should result just be the cpu_sum column.
  auto map_node_status = FindNodeType(ir_graph, IRNodeType::kMap);
  EXPECT_OK(map_node_status);
  auto map_node = static_cast<MapIR*>(map_node_status.ConsumeValueOrDie());
  table_store::schema::Relation test_map_relation;
  test_map_relation.AddColumn(types::FLOAT64, "cpu_sum");
  EXPECT_TRUE(RelationEquality(map_node->relation(), test_map_relation));
}

TEST_F(AnalyzerTest, test_relation_multi_col_agg) {
  std::string chain_operators = absl::StrJoin(
      {"queryDF = From(table='cpu', select=['cpu0', 'cpu1', 'cpu2']).Range(start=0,stop=10)",
       "aggDF = queryDF.Agg(by=lambda r : [r.cpu0, r.cpu2], fn=lambda r : {'cpu_count' : "
       "pl.count(r.cpu1), 'cpu_mean' : pl.mean(r.cpu1)}).Result(name='cpu_out')"},
      "\n");
  auto ir_graph_status = CompileGraph(chain_operators);
  auto ir_graph = ir_graph_status.ConsumeValueOrDie();
  auto handle_status = HandleRelation(ir_graph);
  VLOG(1) << handle_status.ToString();
  ASSERT_OK(handle_status);

  auto agg_node_status = FindNodeType(ir_graph, IRNodeType::kBlockingAgg);
  EXPECT_OK(agg_node_status);
  auto agg_node = static_cast<BlockingAggIR*>(agg_node_status.ConsumeValueOrDie());
  table_store::schema::Relation test_agg_relation;
  test_agg_relation.AddColumn(types::INT64, "cpu_count");
  test_agg_relation.AddColumn(types::FLOAT64, "cpu_mean");
  test_agg_relation.AddColumn(types::FLOAT64, "cpu0");
  test_agg_relation.AddColumn(types::FLOAT64, "cpu2");
  EXPECT_TRUE(RelationEquality(agg_node->relation(), test_agg_relation));
}

TEST_F(AnalyzerTest, test_from_select) {
  // operators don't use generated columns, are just chained.
  std::string chain_operators =
      "queryDF = From(table='cpu', select=['cpu0', "
      "'cpu2']).Range(start=0,stop=10).Result(name='cpu_out')";
  table_store::schema::Relation test_relation;
  test_relation.AddColumn(types::FLOAT64, "cpu0");
  test_relation.AddColumn(types::FLOAT64, "cpu2");
  auto ir_graph_status = CompileGraph(chain_operators);
  auto ir_graph = ir_graph_status.ConsumeValueOrDie();
  auto handle_status = HandleRelation(ir_graph);
  auto sink_node_status = FindNodeType(ir_graph, IRNodeType::kMemorySink);
  EXPECT_OK(sink_node_status);
  auto sink_node = static_cast<MemorySinkIR*>(sink_node_status.ConsumeValueOrDie());
  EXPECT_TRUE(RelationEquality(sink_node->relation(), test_relation));
}

// Test to make sure the system detects udfs/udas that don't exist.
TEST_F(AnalyzerTest, nonexistant_udfs) {
  std::string missing_udf =
      absl::StrJoin({"queryDF = From(table='cpu', select=['cpu0', 'cpu1']).Range(start=0,stop=10)",
                     "mapDF = queryDF.Map(fn=lambda r : {'cpu_sum' : "
                     "pl.sus(r.cpu0,r.cpu1)}).Result(name='cpu_out')"},
                    "\n");

  auto ir_graph_status = CompileGraph(missing_udf);
  ASSERT_OK(ir_graph_status);
  auto ir_graph = ir_graph_status.ConsumeValueOrDie();
  auto handle_status = HandleRelation(ir_graph);
  EXPECT_FALSE(handle_status.ok());
  std::string missing_uda =
      absl::StrJoin({"queryDF = From(table='cpu', select=['cpu0', 'cpu1']).Range(start=0,stop=10)",
                     "aggDF = queryDF.Agg(by=lambda r : r.cpu0, fn=lambda r : {'cpu_count' : "
                     "pl.punt(r.cpu1)}).Result(name='cpu_out')"},
                    "\n");

  ir_graph_status = CompileGraph(missing_uda);
  ASSERT_OK(ir_graph_status);
  ir_graph = ir_graph_status.ConsumeValueOrDie();
  handle_status = HandleRelation(ir_graph);
  EXPECT_FALSE(handle_status.ok());
}

TEST_F(AnalyzerTest, nonexistant_cols) {
  // Test for columns used in map function that don't exist in relation.
  std::string wrong_column_map_func =
      absl::StrJoin({"queryDF = From(table='cpu', select=['cpu0', 'cpu1']).Range(start=0,stop=10)",
                     "mapDF = queryDF.Map(fn=lambda r : {'cpu_sum' : "
                     "pl.sum(r.cpu0,r.cpu100)}).Result(name='cpu_out')"},
                    "\n");

  auto ir_graph_status = CompileGraph(wrong_column_map_func);
  ASSERT_OK(ir_graph_status);
  auto ir_graph = ir_graph_status.ConsumeValueOrDie();
  auto handle_status = HandleRelation(ir_graph);
  EXPECT_FALSE(handle_status.ok());
  VLOG(1) << handle_status.status().ToString();

  // Test for columns used in group_by arg of Agg that don't exist.
  std::string wrong_column_agg_by =
      absl::StrJoin({"queryDF = From(table='cpu', select=['cpu0', 'cpu1']).Range(start=0,stop=10)",
                     "aggDF = queryDF.Agg(by=lambda r : r.cpu101, fn=lambda r : {'cpu_count' "
                     ": "
                     "pl.count(r.cpu1)}).Result(name='cpu_out')"},
                    "\n");
  ir_graph_status = CompileGraph(wrong_column_agg_by);
  ASSERT_OK(ir_graph_status);
  ir_graph = ir_graph_status.ConsumeValueOrDie();
  handle_status = HandleRelation(ir_graph);
  EXPECT_FALSE(handle_status.ok());
  VLOG(1) << handle_status.status().ToString();

  // Test for column not selected in From.
  std::string not_selected_col =
      absl::StrJoin({"queryDF = From(table='cpu', select=['cpu0', 'cpu2']).Range(start=0,stop=10)",
                     "aggDF = queryDF.Agg(by=lambda r : r.cpu0, fn=lambda r : {'cpu_count' : "
                     "pl.count(r.cpu1)}).Result(name='cpu_out')"},
                    "\n");
  ir_graph_status = CompileGraph(not_selected_col);
  ASSERT_OK(ir_graph_status);
  ir_graph = ir_graph_status.ConsumeValueOrDie();
  handle_status = HandleRelation(ir_graph);
  EXPECT_FALSE(handle_status.ok());
  VLOG(1) << handle_status.status().ToString();
}

// Use results of created columns in later parts of the pipeline.
TEST_F(AnalyzerTest, created_columns) {
  std::string agg_use_map_col_fn = absl::StrJoin(
      {"queryDF = From(table='cpu', select=['cpu0', 'cpu1', 'cpu2']).Range(start=0,stop=10)",
       "mapDF = queryDF.Map(fn=lambda r : {'cpu2' : r.cpu2, 'cpu_sum' : r.cpu0+r.cpu1})",
       "aggDF = mapDF.Agg(by=lambda r : r.cpu2, fn=lambda r : {'cpu_count' : "
       "pl.count(r.cpu_sum)}).Result(name='cpu_out')"},
      "\n");
  auto ir_graph_status = CompileGraph(agg_use_map_col_fn);
  ASSERT_OK(ir_graph_status);
  auto ir_graph = ir_graph_status.ConsumeValueOrDie();
  auto handle_status = HandleRelation(ir_graph);
  EXPECT_OK(handle_status);
  VLOG(1) << handle_status.status().ToString();

  std::string agg_use_map_col_by = absl::StrJoin(
      {"queryDF = From(table='cpu', select=['cpu0', 'cpu1', 'cpu2']).Range(start=0,stop=10)",
       "mapDF = queryDF.Map(fn=lambda r : {'cpu2' : r.cpu2, 'cpu_sum' : r.cpu0+r.cpu1})",
       "aggDF = mapDF.Agg(by=lambda r : r.cpu_sum, fn=lambda r : {'cpu_count' : "
       "pl.count(r.cpu2)}).Result(name='cpu_out')"},
      "\n");
  ir_graph_status = CompileGraph(agg_use_map_col_by);
  ASSERT_OK(ir_graph_status);
  ir_graph = ir_graph_status.ConsumeValueOrDie();
  handle_status = HandleRelation(ir_graph);
  EXPECT_OK(handle_status);
  VLOG(1) << handle_status.status().ToString();

  std::string map_use_agg_col = absl::StrJoin(
      {
          "queryDF = From(table='cpu', select=['cpu0', 'cpu1', 'cpu2']).Range(start=0,stop=10)",
          "aggDF = queryDF.Agg(by=lambda r : r.cpu1, fn=lambda r : {'cpu0_mean' : "
          "pl.mean(r.cpu0), "
          "'cpu1_mean' : pl.mean(r.cpu1)})",
          "mapDF = aggDF.Map(fn=lambda r : {'cpu_sum' : "
          "r.cpu1_mean+r.cpu1_mean}).Result(name='cpu_out')",
      },
      "\n");
  ir_graph_status = CompileGraph(map_use_agg_col);
  ASSERT_OK(ir_graph_status);
  ir_graph = ir_graph_status.ConsumeValueOrDie();
  handle_status = HandleRelation(ir_graph);
  EXPECT_OK(handle_status);
  VLOG(1) << handle_status.status().ToString();

  std::string map_use_map_col = absl::StrJoin(
      {"queryDF = From(table='cpu', select=['cpu0', 'cpu1', 'cpu2']).Range(start=0,stop=10)",
       "mapDF = queryDF.Map(fn=lambda r : {'cpu2': r.cpu2, 'cpu_sum' : r.cpu0+r.cpu1})",
       "map2Df = mapDF.Map(fn=lambda r : {'cpu_sum2' : r.cpu2+r.cpu_sum}).Result(name='cpu_out')"},
      "\n");
  ir_graph_status = CompileGraph(map_use_map_col);
  ASSERT_OK(ir_graph_status);
  ir_graph = ir_graph_status.ConsumeValueOrDie();
  handle_status = HandleRelation(ir_graph);
  EXPECT_OK(handle_status);
  VLOG(1) << handle_status.status().ToString();

  std::string agg_use_agg_col = absl::StrJoin(
      {"queryDF = From(table='cpu', select=['cpu0', 'cpu1', 'cpu2']).Range(start=0,stop=10)",
       "aggDF = queryDF.Agg(by=lambda r : r.cpu1, fn=lambda r : {'cpu0_mean' : pl.mean(r.cpu0), "
       "'cpu1_mean' : pl.mean(r.cpu1)})",
       "agg2DF = aggDF.Agg(by=lambda r : r.cpu1_mean, fn=lambda r : {'cpu0_mean_mean' : "
       "pl.mean(r.cpu0_mean)}).Result(name='cpu_out') "},
      "\n");
  ir_graph_status = CompileGraph(agg_use_agg_col);
  ASSERT_OK(ir_graph_status);
  ir_graph = ir_graph_status.ConsumeValueOrDie();
  handle_status = HandleRelation(ir_graph);
  EXPECT_OK(handle_status);
  VLOG(1) << handle_status.status().ToString();
}

TEST_F(AnalyzerTest, non_float_columns) {
  std::string agg_fn_count_all = absl::StrJoin(
      {
          "queryDF = From(table='non_float_table', select=['float_col', 'int_col', 'bool_col', "
          "'string_col']).Range(start=0,stop=10)",
          "aggDF = queryDF.Agg(by=lambda r : r.float_col, fn=lambda r : {"
          "'int_count' : pl.count(r.int_col), "
          "'bool_count' : pl.count(r.bool_col),"
          " 'string_count' : pl.count(r.string_col)}).Result(name='cpu_out')",
      },
      "\n");
  auto ir_graph_status = CompileGraph(agg_fn_count_all);
  ASSERT_OK(ir_graph_status);
  auto ir_graph = ir_graph_status.ConsumeValueOrDie();
  auto handle_status = HandleRelation(ir_graph);
  EXPECT_OK(handle_status);
  VLOG(1) << handle_status.status().ToString();

  std::string by_fn_count_all = absl::StrJoin(
      {
          "queryDF = From(table='non_float_table', select=['float_col', 'int_col', 'bool_col', "
          "'string_col']).Range(start=0,stop=10)",
          "aggDF = queryDF.Agg(by=lambda r : r.int_col, fn=lambda r : {"
          "'float_count' : pl.count(r.float_col), "
          "'bool_count' : pl.count(r.bool_col),"
          " 'string_count' : pl.count(r.string_col)}).Result(name='cpu_out')",
      },
      "\n");
  ir_graph_status = CompileGraph(by_fn_count_all);
  ASSERT_OK(ir_graph_status);
  ir_graph = ir_graph_status.ConsumeValueOrDie();
  handle_status = HandleRelation(ir_graph);
  EXPECT_OK(handle_status);
  VLOG(1) << handle_status.status().ToString();
}

TEST_F(AnalyzerTest, assign_udf_func_ids) {
  std::string chain_operators = absl::StrJoin(
      {"queryDF = From(table='cpu', select=['cpu0', 'cpu1', 'cpu2']).Range(start=0,stop=10)",
       "mapDF = queryDF.Map(fn=lambda r : {'cpu_sub': r.cpu0 - r.cpu1, 'cpu_sum': r.cpu0+r.cpu1, "
       "'cpu_sum2': r.cpu2 + r.cpu1})",
       "mapDF.Result(name='cpu_out')"},
      "\n");
  auto ir_graph_status = CompileGraph(chain_operators);
  auto ir_graph = ir_graph_status.ConsumeValueOrDie();
  auto handle_status = HandleRelation(ir_graph);
  EXPECT_OK(handle_status);

  // Map relation should be contain cpu0, cpu1, and cpu_sum.
  auto map_node_status = FindNodeType(ir_graph, IRNodeType::kMap);
  EXPECT_OK(map_node_status);
  auto map_node = static_cast<MapIR*>(map_node_status.ConsumeValueOrDie());

  auto lambda_func = static_cast<LambdaIR*>(map_node->lambda_func());
  auto func_node = static_cast<FuncIR*>(lambda_func->col_exprs()[0].node);
  EXPECT_EQ(0, func_node->func_id());
  func_node = static_cast<FuncIR*>(lambda_func->col_exprs()[1].node);
  EXPECT_EQ(1, func_node->func_id());
  func_node = static_cast<FuncIR*>(lambda_func->col_exprs()[2].node);
  EXPECT_EQ(1, func_node->func_id());
}

TEST_F(AnalyzerTest, assign_uda_func_ids) {
  std::string chain_operators = absl::StrJoin(
      {"queryDF = From(table='cpu', select=['cpu0', 'cpu1', 'cpu2']).Range(start=0,stop=10)",
       "aggDF = queryDF.Agg(by=lambda r: r.cpu0, fn=lambda r: {'cnt': pl.count(r.cpu1), 'mean': "
       "pl.mean(r.cpu2)})",
       "aggDF.Result(name='cpu_out')"},
      "\n");
  auto ir_graph_status = CompileGraph(chain_operators);
  auto ir_graph = ir_graph_status.ConsumeValueOrDie();
  auto handle_status = HandleRelation(ir_graph);
  EXPECT_OK(handle_status);

  // Map relation should be contain cpu0, cpu1, and cpu_sum.
  auto agg_node_status = FindNodeType(ir_graph, IRNodeType::kBlockingAgg);
  EXPECT_OK(agg_node_status);
  auto agg_node = static_cast<BlockingAggIR*>(agg_node_status.ConsumeValueOrDie());

  auto lambda_func = static_cast<LambdaIR*>(agg_node->agg_func());
  auto func_node = static_cast<FuncIR*>(lambda_func->col_exprs()[0].node);
  EXPECT_EQ(0, func_node->func_id());
  func_node = static_cast<FuncIR*>(lambda_func->col_exprs()[1].node);
  EXPECT_EQ(1, func_node->func_id());
}

TEST_F(AnalyzerTest, select_all) {
  std::string select_all = "queryDF = From(table='cpu').Result(name='cpu_out')";
  auto ir_graph_status = CompileGraph(select_all);
  ASSERT_OK(ir_graph_status);
  auto ir_graph = ir_graph_status.ConsumeValueOrDie();
  ASSERT_OK(HandleRelation(ir_graph));

  // Map relation should be contain cpu0, cpu1, and cpu_sum.
  auto sink_node_status = FindNodeType(ir_graph, IRNodeType::kMemorySink);
  EXPECT_OK(sink_node_status);
  auto sink_node = static_cast<MemorySinkIR*>(sink_node_status.ConsumeValueOrDie());
  auto relation_map = compiler_state_->relation_map();
  ASSERT_NE(relation_map->find("cpu"), relation_map->end());
  auto expected_relation = relation_map->find("cpu")->second;
  EXPECT_EQ(expected_relation.col_types(), sink_node->relation().col_types());
  EXPECT_EQ(expected_relation.col_names(), sink_node->relation().col_names());
}

class MetadataSingleOps : public AnalyzerTest, public ::testing::WithParamInterface<std::string> {};
TEST_P(MetadataSingleOps, valid_metadata_calls) {
  std::string op_call = GetParam();
  std::string valid_query = absl::StrJoin(
      {"queryDF = From(table='cpu') ", "opDF = queryDF.$0", "opDF.Result(name='out')"}, "\n");
  valid_query = absl::Substitute(valid_query, op_call);
  VLOG(1) << valid_query;
  auto ir_graph_status = CompileGraph(valid_query);
  ASSERT_OK(ir_graph_status);
  auto ir_graph = ir_graph_status.ConsumeValueOrDie();
  ASSERT_OK(HandleRelation(ir_graph));
}
std::vector<std::string> metadata_operators{
    "Filter(fn=lambda r : r.attr.service == 'pl/orders')",
    "Map(fn=lambda r: {'service': r.attr.service})",
    "Agg(fn=lambda r: pl.mean(r.cpu0), by=lambda r: r.attr.service)",
    "Agg(fn=lambda r: pl.count(r.cpu0), by=lambda r: [r.cpu0, r.attr.service])",
    "Agg(fn=lambda r: pl.count(r.cpu0), by=lambda r: r.attr.service).Filter(fn=lambda r: "
    "r.attr.service == 'pl/orders')",
    "Agg(fn=lambda r: pl.count(r.cpu0), by=lambda r: r.attr.service_id).Filter(fn=lambda r: "
    "r.attr.service == 'pl/orders')"};

INSTANTIATE_TEST_CASE_P(MetadataAttributesSuite, MetadataSingleOps,
                        ::testing::ValuesIn(metadata_operators));
TEST_F(AnalyzerTest, metadata_fails_no_upid) {
  std::string op_call = "Map(fn=lambda r: {'service': r.attr.service})";
  std::string valid_query = absl::StrJoin({"queryDF = From(table='cpu', select=['cpu0']) ",
                                           "opDF = queryDF.$0", "opDF.Result(name='out')"},
                                          "\n");
  valid_query = absl::Substitute(valid_query, op_call);
  VLOG(1) << valid_query;
  auto ir_graph_status = CompileGraph(valid_query);
  ASSERT_OK(ir_graph_status);
  auto ir_graph = ir_graph_status.ConsumeValueOrDie();
  EXPECT_THAT(
      HandleRelation(ir_graph),
      HasCompilerError("Can't resolve metadata because of lack of converting columns in the "
                       "parent. Need one of [upid,_attr_service_id]. Parent relation has "
                       "columns [cpu0] available."));
}

TEST_F(AnalyzerTest, define_column_metadata) {
  std::string valid_query =
      absl::StrJoin({"queryDF = From(table='cpu', select=['cpu0']) ",
                     "opDF = queryDF.Map(fn=lambda r:{'$0service': pl.add(r.cpu0, 1)})",
                     "opDF.Result(name='out')"},
                    "\n");
  valid_query = absl::Substitute(valid_query, MetadataProperty::kMetadataColumnPrefix);
  auto ir_graph_status = CompileGraph(valid_query);
  ASSERT_OK(ir_graph_status);
  auto ir_graph = ir_graph_status.ConsumeValueOrDie();
  EXPECT_THAT(HandleRelation(ir_graph),
              HasCompilerError("Column name '$0service' violates naming rules. The '$0' prefix is "
                               "reserved for internal use.",
                               MetadataProperty::kMetadataColumnPrefix));
}

// Test to make sure that copying the metadata key column still works.
TEST_F(AnalyzerTest, copy_metadata_key_and_og_column) {
  std::string valid_query = absl::StrJoin(
      {"queryDF = From(table='cpu') ",
       "opDF = queryDF.Agg(by=lambda r: [r.$0, r.attr.service],  fn=lambda "
       "r:{'mean_cpu': pl.mean(r.cpu0)}).Filter(fn=lambda r: r.attr.service=='pl/service-name')",
       "opDF.Result(name='out')"},
      "\n");
  valid_query = absl::Substitute(valid_query, MetadataProperty::kUniquePIDColumn);
  auto ir_graph_status = CompileGraph(valid_query);
  ASSERT_OK(ir_graph_status);
  auto ir_graph = ir_graph_status.ConsumeValueOrDie();
  EXPECT_OK(HandleRelation(ir_graph));
}

}  // namespace compiler
}  // namespace carnot
}  // namespace pl
