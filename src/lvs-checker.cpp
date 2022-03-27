#include "lvs-checker.hpp"
#include <coroutine>

namespace lvs {

using ndn::Name;
using generator::Generator;
using generator::StopIteration;

std::map<std::string, Name::Component> Checker::ContextToName(const Checker::Context& context)
{
  auto ret = std::map<std::string, Name::Component>();
  for(int i = 0, cnt = context.size(); i < cnt; i ++) {
    if(context[i].has_value()){
      ret[symbols[i]] = *context[i];
    }
  }
  return ret;
}

bool Checker::CheckConstraints(Name::Component value,
                               const Checker::Context& context,
                               const std::vector<PatternConstraint>& cons_sets)
{
  for(auto&& cons: cons_sets) {
    bool satisfied = false;
    for(auto&& option: cons.options) {
      if(option.value.has_value()) {
        if(value == Name::Component(ndn::Block(option.value->data(), option.value->size()))) {
          satisfied = true;
          break;
        }
      } else if(option.tag.has_value()) {
        if(value == context[*option.tag]) {
          satisfied = true;
          break;
        }
      } else {
        assert(option.fn.has_value());  // Sanity checked
        auto fn_id = option.fn->fn_id;
        if(!user_fns.contains(fn_id)){
          throw LvsModelError("User function " + fn_id + " is undefined");
        }
        auto arg_list = std::vector<Name::Component>();
        arg_list.reserve(option.fn->args.size());
        for(auto&& arg: option.fn->args) {
          if(arg.value.has_value()) {
            arg_list.push_back(Name::Component(ndn::Block(arg.value->data(), arg.value->size())));
          } else {
            assert(arg.tag.has_value());  // Sanity checked
            auto value = context[*arg.tag];
            if(value.has_value()){
              arg_list.push_back(*value);
            } else {
              arg_list.push_back(Name::Component());
            }
          }
        }
        if(user_fns[fn_id](value, arg_list)) {
          satisfied = true;
          break;
        }
      }
    }
    if(!satisfied){
      return false;
    }
  }
  return true;
}

Generator<std::tuple<uint64_t, const Checker::Context*>>
Checker::match(const ndn::Name& name, const Checker::Context& context) {
  std::optional<uint64_t> cur = model.start_id;
  int edge_index = -1;
  auto edge_indices = std::vector<int>();
  Context con = Context(context);
  if(con.size() < model.named_pattern_cnt + 1){
    con.resize(model.named_pattern_cnt + 1, std::nullopt);
  }
  auto matches = std::vector<int>();
  while(cur.has_value()){
    auto depth = edge_indices.size();
    auto&& node = model.nodes[*cur];
    bool backtrack = false;
    if(depth == name.size()) {
      co_yield {*cur, &con};
    } else {
      // Make movements
      if(edge_index < 0){
        // Value edge: since it matches at most once, ignore edge_index
        edge_index = 0;
        for(auto&& ve: node.v_edges) {
          if(name[depth] == Name::Component(ndn::Block(ve.value.data(), ve.value.size()))) {
            edge_indices.push_back(0);
            matches.push_back(0);
            cur = ve.dest;
            edge_index = -1;
            break;
          }
        }
      } else if(size_t(edge_index) < node.p_edges.size()) {
        // Pattern edge: check condition and make a move
        auto& pe = node.p_edges[edge_index];
        edge_index ++;
        auto& value = name[depth];
        if(pe.tag <= model.named_pattern_cnt && con[pe.tag]){
          if(value != *con[pe.tag]){
            continue;
          }
          matches.push_back(-1);
        } else {
          if(!CheckConstraints(value, con, pe.cons_sets)){
            continue;
          }
          if(pe.tag <= model.named_pattern_cnt) {
            con[pe.tag] = value;
            matches.push_back(pe.tag);
          } else {
            matches.push_back(-1);
          }
        }
        edge_indices.push_back(edge_index);
        cur = pe.dest;
        edge_index = -1;
      } else {
        backtrack = true;
      }
      if(backtrack){
        if(!edge_indices.empty()) {
          edge_index = edge_indices.back();
          edge_indices.pop_back();
        }
        if(!matches.empty()) {
          auto last_tag = matches.back();
          matches.pop_back();
          if(last_tag >= 0) {
            con[last_tag] = std::nullopt;
          }
        }
        cur = node.parent;
      }
    }
  }
  co_return;
}

Generator<std::tuple<const std::vector<std::string>*, std::map<std::string, Name::Component>>>
Checker::match(const ndn::Name& name)
{
  auto matcher = match(name, {});
  while(true){
    auto [node_id, contest_ptr] = matcher.next();
    const Context& context = *contest_ptr;
    auto&& node = model.nodes[node_id];
    co_yield {&node.rule_name, ContextToName(context)};
  }
  co_return;
}

bool Checker::check(const ndn::Name& pkt_name, const ndn::Name& key_name)
{
  auto pkt_matcher = match(pkt_name, {});
  try{
    while(true){
      auto [node_id, contest_ptr] = pkt_matcher.next();
      auto&& pkt_node = model.nodes[node_id];
      const Context& context = *contest_ptr;
      auto key_matcher = match(key_name, context);
      try{
        while(true){
          auto [node_id, contest_ptr] = key_matcher.next();
          for(auto sig_node: pkt_node.sign_cons) {
            if(sig_node == node_id) {
              return true;
            }
          }
        }
      }catch(StopIteration&){
        continue;
      }
    }
  }catch(StopIteration&){
    return false;
  }
}

} // namespace lvs