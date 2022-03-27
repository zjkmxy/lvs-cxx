#pragma once

#include <functional>
#include <vector>
#include <map>
#include <string>
#include <exception>
#include <ndn-cxx/name.hpp>
#include "tlv-encoder.hpp"
#include "lvs-binary.hpp"
#include "generator.hpp"

namespace lvs {

using UserFn = std::function<bool(ndn::Name::Component, const std::vector<ndn::Name::Component>&)>;

struct LvsModelError: std::exception {
  std::string msg;
  LvsModelError(const std::string& msg): msg(msg) {}
  const char* what() const noexcept override {
    return msg.c_str();
  }
};

class Checker {
private:
  LvsModel model;
  std::map<std::string, UserFn> user_fns;
  std::vector<std::string> symbols;

public:
  using Context = std::vector<std::optional<ndn::Name::Component>>;

  Checker(LvsModel model, std::map<std::string, UserFn> user_fns):
    model(model), user_fns(user_fns)
  {
    symbols.resize(model.named_pattern_cnt + 1);
    for(auto&& sym: model.symbols){
      symbols[sym.tag] = sym.ident;
    }
  }

private:
  std::map<std::string, ndn::Name::Component> ContextToName(const Context& context);

  bool CheckConstraints(ndn::Name::Component value,
                        const Context& context,
                        const std::vector<PatternConstraint>& cons_sets);

  generator::Generator<std::tuple<uint64_t, const Context*>>
  match(const ndn::Name& name, const Context& context);

public:
  generator::Generator<std::tuple<const std::vector<std::string>*, std::map<std::string, ndn::Name::Component>>>
  match(const ndn::Name& name);

  bool check(const ndn::Name& pkt_name, const ndn::Name& key_name);
};

} // namespace lvs