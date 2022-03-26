#include <boost-test.hpp>
#include <coroutine>

import generator;

namespace tests {

BOOST_AUTO_TEST_SUITE(TestGenerator)

BOOST_AUTO_TEST_CASE(Generator1) {
  auto factorial = []() -> generator::Generator<uint64_t> {
    uint64_t fac = 1;
    uint64_t x = 1;
    while (true) {
      fac *= x;
      x++;
      if (fac > 1000) {
        co_return;
      }
      co_yield fac;
    }
    co_return;  // never reached
  };

  auto fac = factorial();
  BOOST_CHECK_EQUAL(fac.next(), 1);
  BOOST_CHECK_EQUAL(fac.next(), 2);
  BOOST_CHECK_EQUAL(fac.next(), 6);
  BOOST_CHECK_EQUAL(fac.next(), 24);
  BOOST_CHECK_EQUAL(fac.next(), 120);
  BOOST_CHECK_EQUAL(fac.next(), 720);
  BOOST_CHECK_THROW(fac.next(), generator::StopIteration);
}

BOOST_AUTO_TEST_SUITE_END() // TestGenerator

} // namespace tests