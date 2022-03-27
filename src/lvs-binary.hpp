#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include "tlv-encoder.hpp"

namespace lvs {

namespace type {

const uint64_t COMPONENT_VALUE = 0x01;
const uint64_t PATTERN_TAG = 0x02;
const uint64_t NODE_ID = 0x03;
const uint64_t USER_FN_ID = 0x04;
const uint64_t IDENTIFIER = 0x05;
const uint64_t USER_FN_CALL = 0x11;
const uint64_t FN_ARGS = 0x12;
const uint64_t CONS_OPTION = 0x21;
const uint64_t CONSTRAINT = 0x22;
const uint64_t VALUE_EDGE = 0x31;
const uint64_t PATTERN_EDGE = 0x32;
const uint64_t KEY_NODE_ID = 0x33;
const uint64_t PARENT_ID = 0x34;
const uint64_t VERSION = 0x40;
const uint64_t NODE = 0x41;
const uint64_t TAG_SYMBOL = 0x42;
const uint64_t NAMED_PATTERN_NUM = 0x43;

} // namespace type

struct UserFnArg {
  std::optional<tlv::NameComponent> value;
  std::optional<uint64_t> tag;

  using Parsable = tlv::Struct<UserFnArg,
    tlv::NameComponentFieldOpt<type::COMPONENT_VALUE, UserFnArg, &UserFnArg::value>,
    tlv::NaturalFieldOpt<type::PATTERN_TAG, UserFnArg, &UserFnArg::tag>>;
};

struct UserFnCall {
  std::string fn_id;
  std::vector<UserFnArg> args;

  using Parsable = tlv::Struct<UserFnCall,
    tlv::BytesField<type::USER_FN_ID, UserFnCall, decltype(fn_id), &UserFnCall::fn_id>,
    tlv::StructFieldVec<type::FN_ARGS, UserFnCall, UserFnArg, &UserFnCall::args>>;
};

struct ConstraintOption {
  std::optional<tlv::NameComponent> value;
  std::optional<uint64_t> tag;
  std::optional<UserFnCall> fn;

  using Parsable = tlv::Struct<ConstraintOption,
    tlv::NameComponentFieldOpt<type::COMPONENT_VALUE, ConstraintOption, &ConstraintOption::value>,
    tlv::NaturalFieldOpt<type::PATTERN_TAG, ConstraintOption, &ConstraintOption::tag>,
    tlv::StructFieldOpt<type::USER_FN_CALL, ConstraintOption, UserFnCall, &ConstraintOption::fn>>;
};

struct PatternConstraint {
  std::vector<ConstraintOption> options;

  using Parsable = tlv::Struct<PatternConstraint,
    tlv::StructFieldVec<type::CONS_OPTION, PatternConstraint, ConstraintOption, &PatternConstraint::options>>;
};

struct PatternEdge {
  uint64_t dest;
  uint64_t tag;
  std::vector<PatternConstraint> cons_sets;

  using Parsable = tlv::Struct<PatternEdge,
    tlv::NaturalField<type::NODE_ID, PatternEdge, &PatternEdge::dest>,
    tlv::NaturalField<type::PATTERN_TAG, PatternEdge, &PatternEdge::tag>,
    tlv::StructFieldVec<type::CONSTRAINT, PatternEdge, PatternConstraint, &PatternEdge::cons_sets>>;
};

struct ValueEdge {
  uint64_t dest;
  tlv::NameComponent value;

  using Parsable = tlv::Struct<ValueEdge,
    tlv::NaturalField<type::NODE_ID, ValueEdge, &ValueEdge::dest>,
    tlv::NameComponentField<type::COMPONENT_VALUE, ValueEdge, &ValueEdge::value>>;
};

struct Node {
  uint64_t id;
  std::optional<uint64_t> parent;
  std::vector<std::string> rule_name;
  std::vector<ValueEdge> v_edges;
  std::vector<PatternEdge> p_edges;
  std::vector<uint64_t> sign_cons;

  using Parsable = tlv::Struct<Node,
    tlv::NaturalField<type::NODE_ID, Node, &Node::id>,
    tlv::NaturalFieldOpt<type::PARENT_ID, Node, &Node::parent>,
    tlv::BytesFieldVec<type::IDENTIFIER, Node, std::string, &Node::rule_name>,
    tlv::StructFieldVec<type::VALUE_EDGE, Node, ValueEdge, &Node::v_edges>,
    tlv::StructFieldVec<type::PATTERN_EDGE, Node, PatternEdge, &Node::p_edges>,
    tlv::NaturalFieldVec<type::KEY_NODE_ID, Node, &Node::sign_cons>>;
};

struct TagSymbol {
  uint64_t tag;
  std::string ident;

  using Parsable = tlv::Struct<TagSymbol,
    tlv::NaturalField<type::PATTERN_TAG, TagSymbol, &TagSymbol::tag>,
    tlv::BytesField<type::IDENTIFIER, TagSymbol, std::string, &TagSymbol::ident>>;
};

struct LvsModel {
  uint64_t version;
  uint64_t start_id;
  uint64_t named_pattern_cnt;
  std::vector<Node> nodes;
  std::vector<TagSymbol> symbols;

  using Parsable = tlv::Struct<LvsModel,
    tlv::NaturalField<type::VERSION, LvsModel, &LvsModel::version>,
    tlv::NaturalField<type::NODE_ID, LvsModel, &LvsModel::start_id>,
    tlv::NaturalField<type::NAMED_PATTERN_NUM, LvsModel, &LvsModel::named_pattern_cnt>,
    tlv::StructFieldVec<type::NODE, LvsModel, Node, &LvsModel::nodes>,
    tlv::StructFieldVec<type::TAG_SYMBOL, LvsModel, TagSymbol, &LvsModel::symbols>>;

  template<typename B>
  static inline std::optional<LvsModel> Parse(const B& wire) {
    auto [ret, len] = Parsable::Parse(wire);
    if(len != wire.size()){
      return std::nullopt;
    } else {
      return ret;
    }
  }
};

} // namespace lvs
