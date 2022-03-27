#pragma once

#include <iostream>
#include <string>
#include <exception>
#include <optional>
#if defined(__GNUC__) && (__GNUC__ >= 10)
#include <coroutine>
#else
#include <experimental/coroutine>
#endif

namespace generator {

#if defined(__GNUC__) && (__GNUC__ >= 10)
using std::coroutine_handle;
using std::suspend_always;
#else
using std::experimental::coroutine_handle;
using std::experimental::suspend_always;
#endif

struct StopIteration: std::exception {
  StopIteration() = default;
  ~StopIteration() override {}
};

template <typename T>
struct Generator {
  struct promise_type {
    Generator<T> get_return_object() {
      return Generator<T>{coroutine_handle<promise_type>::from_promise(*this)};
    }
    auto initial_suspend() { return suspend_always(); }
    // suspend_never() will cause problem: clang crashes with unable to create an object;
    // gcc will not crash but have a memory access error.
    auto final_suspend() noexcept { return suspend_always(); }
    auto yield_value(T value) {
      yielded_value = value;
      return suspend_always();
    }
    void return_void() {
      yielded_value = std::nullopt;
    }
    void unhandled_exception() {}
    std::optional<T> yielded_value;
  };

  T next() {
    handle.resume();
    const auto& promise = handle.promise();
    if (!promise.yielded_value.has_value()) {
      throw StopIteration{};
    }else{
      return promise.yielded_value.value();
    }
  }
  coroutine_handle<promise_type> handle;
};

} // namespace generator