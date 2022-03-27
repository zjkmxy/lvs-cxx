#include <boost-test.hpp>

#include "lvs-binary.hpp"
#include "lvs-checker.hpp"

namespace tests {

BOOST_AUTO_TEST_SUITE(TestLvs)

BOOST_AUTO_TEST_CASE(Binary1) {
  std::uint8_t buffer[] = {
    0x40, 0x04, 0x00, 0x01, 0x00, 0x00, 0x03, 0x01, 0x00, 0x43, 0x01, 0x06, 0x41, 0x3E, 0x03, 0x01,
    0x00, 0x32, 0x16, 0x03, 0x01, 0x01, 0x02, 0x01, 0x01, 0x22, 0x0E, 0x21, 0x05, 0x01, 0x03, 0x08,
    0x01, 0x61, 0x21, 0x05, 0x01, 0x03, 0x08, 0x01, 0x78, 0x32, 0x06, 0x03, 0x01, 0x04, 0x02, 0x01,
    0x01, 0x32, 0x11, 0x03, 0x01, 0x07, 0x02, 0x01, 0x04, 0x22, 0x09, 0x21, 0x07, 0x01, 0x05, 0x08,
    0x03, 0x78, 0x78, 0x78, 0x32, 0x06, 0x03, 0x01, 0x0A, 0x02, 0x01, 0x04, 0x41, 0x0E, 0x03, 0x01,
    0x01, 0x34, 0x01, 0x00, 0x32, 0x06, 0x03, 0x01, 0x02, 0x02, 0x01, 0x02, 0x41, 0x1C, 0x03, 0x01,
    0x02, 0x34, 0x01, 0x01, 0x32, 0x14, 0x03, 0x01, 0x03, 0x02, 0x01, 0x03, 0x22, 0x05, 0x21, 0x03,
    0x02, 0x01, 0x02, 0x22, 0x05, 0x21, 0x03, 0x02, 0x01, 0x01, 0x41, 0x11, 0x03, 0x01, 0x03, 0x34,
    0x01, 0x02, 0x05, 0x03, 0x23, 0x72, 0x31, 0x33, 0x01, 0x09, 0x33, 0x01, 0x0C, 0x41, 0x1E, 0x03,
    0x01, 0x04, 0x34, 0x01, 0x00, 0x32, 0x16, 0x03, 0x01, 0x05, 0x02, 0x01, 0x02, 0x22, 0x0E, 0x21,
    0x05, 0x01, 0x03, 0x08, 0x01, 0x62, 0x21, 0x05, 0x01, 0x03, 0x08, 0x01, 0x79, 0x41, 0x0E, 0x03,
    0x01, 0x05, 0x34, 0x01, 0x04, 0x32, 0x06, 0x03, 0x01, 0x06, 0x02, 0x01, 0x03, 0x41, 0x11, 0x03,
    0x01, 0x06, 0x34, 0x01, 0x05, 0x05, 0x03, 0x23, 0x72, 0x31, 0x33, 0x01, 0x09, 0x33, 0x01, 0x0C,
    0x41, 0x0E, 0x03, 0x01, 0x07, 0x34, 0x01, 0x00, 0x32, 0x06, 0x03, 0x01, 0x08, 0x02, 0x01, 0x05,
    0x41, 0x0E, 0x03, 0x01, 0x08, 0x34, 0x01, 0x07, 0x32, 0x06, 0x03, 0x01, 0x09, 0x02, 0x01, 0x06,
    0x41, 0x0B, 0x03, 0x01, 0x09, 0x34, 0x01, 0x08, 0x05, 0x03, 0x23, 0x72, 0x32, 0x41, 0x19, 0x03,
    0x01, 0x0A, 0x34, 0x01, 0x00, 0x32, 0x11, 0x03, 0x01, 0x0B, 0x02, 0x01, 0x05, 0x22, 0x09, 0x21,
    0x07, 0x01, 0x05, 0x08, 0x03, 0x79, 0x79, 0x79, 0x41, 0x0E, 0x03, 0x01, 0x0B, 0x34, 0x01, 0x0A,
    0x32, 0x06, 0x03, 0x01, 0x0C, 0x02, 0x01, 0x06, 0x41, 0x0B, 0x03, 0x01, 0x0C, 0x34, 0x01, 0x0B,
    0x05, 0x03, 0x23, 0x72, 0x33, 0x42, 0x06, 0x02, 0x01, 0x01, 0x05, 0x01, 0x61, 0x42, 0x06, 0x02,
    0x01, 0x02, 0x05, 0x01, 0x62, 0x42, 0x06, 0x02, 0x01, 0x03, 0x05, 0x01, 0x63, 0x42, 0x06, 0x02,
    0x01, 0x04, 0x05, 0x01, 0x78, 0x42, 0x06, 0x02, 0x01, 0x05, 0x05, 0x01, 0x79, 0x42, 0x06, 0x02,
    0x01, 0x06, 0x05, 0x01, 0x7A,
  };
  tlv::bstring_view buf(buffer, sizeof(buffer));

  auto model = lvs::LvsModel::Parse(buf);
  BOOST_CHECK(model.has_value());
  BOOST_CHECK_EQUAL(model->version, 0x00010000);
  BOOST_CHECK_EQUAL(model->nodes.size(), 13);

  std::uint8_t component[] = {0x08, 0x03, 'x', 'x', 'x'};
  BOOST_CHECK_EQUAL(model->nodes[0].p_edges.size(), 4);
  BOOST_CHECK_EQUAL(model->nodes[0].p_edges[2].cons_sets.size(), 1);
  BOOST_CHECK(model->nodes[0].p_edges[2].cons_sets[0].options[0].value.value()
              == tlv::bstring_view(component, sizeof(component)));
} 

BOOST_AUTO_TEST_CASE(Check1) {
  std::uint8_t buffer[] = {
    0x40, 0x04, 0x00, 0x01, 0x00, 0x00, 0x03, 0x01, 0x00, 0x43, 0x01, 0x06, 0x41, 0x3E, 0x03, 0x01,
    0x00, 0x32, 0x16, 0x03, 0x01, 0x01, 0x02, 0x01, 0x01, 0x22, 0x0E, 0x21, 0x05, 0x01, 0x03, 0x08,
    0x01, 0x61, 0x21, 0x05, 0x01, 0x03, 0x08, 0x01, 0x78, 0x32, 0x06, 0x03, 0x01, 0x04, 0x02, 0x01,
    0x01, 0x32, 0x11, 0x03, 0x01, 0x07, 0x02, 0x01, 0x04, 0x22, 0x09, 0x21, 0x07, 0x01, 0x05, 0x08,
    0x03, 0x78, 0x78, 0x78, 0x32, 0x06, 0x03, 0x01, 0x0A, 0x02, 0x01, 0x04, 0x41, 0x0E, 0x03, 0x01,
    0x01, 0x34, 0x01, 0x00, 0x32, 0x06, 0x03, 0x01, 0x02, 0x02, 0x01, 0x02, 0x41, 0x1C, 0x03, 0x01,
    0x02, 0x34, 0x01, 0x01, 0x32, 0x14, 0x03, 0x01, 0x03, 0x02, 0x01, 0x03, 0x22, 0x05, 0x21, 0x03,
    0x02, 0x01, 0x02, 0x22, 0x05, 0x21, 0x03, 0x02, 0x01, 0x01, 0x41, 0x11, 0x03, 0x01, 0x03, 0x34,
    0x01, 0x02, 0x05, 0x03, 0x23, 0x72, 0x31, 0x33, 0x01, 0x09, 0x33, 0x01, 0x0C, 0x41, 0x1E, 0x03,
    0x01, 0x04, 0x34, 0x01, 0x00, 0x32, 0x16, 0x03, 0x01, 0x05, 0x02, 0x01, 0x02, 0x22, 0x0E, 0x21,
    0x05, 0x01, 0x03, 0x08, 0x01, 0x62, 0x21, 0x05, 0x01, 0x03, 0x08, 0x01, 0x79, 0x41, 0x0E, 0x03,
    0x01, 0x05, 0x34, 0x01, 0x04, 0x32, 0x06, 0x03, 0x01, 0x06, 0x02, 0x01, 0x03, 0x41, 0x11, 0x03,
    0x01, 0x06, 0x34, 0x01, 0x05, 0x05, 0x03, 0x23, 0x72, 0x31, 0x33, 0x01, 0x09, 0x33, 0x01, 0x0C,
    0x41, 0x0E, 0x03, 0x01, 0x07, 0x34, 0x01, 0x00, 0x32, 0x06, 0x03, 0x01, 0x08, 0x02, 0x01, 0x05,
    0x41, 0x0E, 0x03, 0x01, 0x08, 0x34, 0x01, 0x07, 0x32, 0x06, 0x03, 0x01, 0x09, 0x02, 0x01, 0x06,
    0x41, 0x0B, 0x03, 0x01, 0x09, 0x34, 0x01, 0x08, 0x05, 0x03, 0x23, 0x72, 0x32, 0x41, 0x19, 0x03,
    0x01, 0x0A, 0x34, 0x01, 0x00, 0x32, 0x11, 0x03, 0x01, 0x0B, 0x02, 0x01, 0x05, 0x22, 0x09, 0x21,
    0x07, 0x01, 0x05, 0x08, 0x03, 0x79, 0x79, 0x79, 0x41, 0x0E, 0x03, 0x01, 0x0B, 0x34, 0x01, 0x0A,
    0x32, 0x06, 0x03, 0x01, 0x0C, 0x02, 0x01, 0x06, 0x41, 0x0B, 0x03, 0x01, 0x0C, 0x34, 0x01, 0x0B,
    0x05, 0x03, 0x23, 0x72, 0x33, 0x42, 0x06, 0x02, 0x01, 0x01, 0x05, 0x01, 0x61, 0x42, 0x06, 0x02,
    0x01, 0x02, 0x05, 0x01, 0x62, 0x42, 0x06, 0x02, 0x01, 0x03, 0x05, 0x01, 0x63, 0x42, 0x06, 0x02,
    0x01, 0x04, 0x05, 0x01, 0x78, 0x42, 0x06, 0x02, 0x01, 0x05, 0x05, 0x01, 0x79, 0x42, 0x06, 0x02,
    0x01, 0x06, 0x05, 0x01, 0x7A,
  };
  tlv::bstring_view buf(buffer, sizeof(buffer));

  auto model = lvs::LvsModel::Parse(buf);
  BOOST_CHECK(model.has_value());

  auto checker = lvs::Checker(*model, {});
  ndn::Name pkt_name("/a/b/c");
  ndn::Name key_name("/xxx/yyy/zzz");
  BOOST_CHECK(checker.check(pkt_name, key_name));
}

BOOST_AUTO_TEST_CASE(Check2) {
  std::uint8_t buffer[] = {
    0x40, 0x04, 0x00, 0x01, 0x00, 0x00, 0x03, 0x01, 0x00, 0x43, 0x01, 0x01, 0x41, 0x1F, 0x03, 0x01,
    0x00, 0x31, 0x0E, 0x03, 0x01, 0x01, 0x01, 0x09, 0x08, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C,
    0x65, 0x31, 0x0A, 0x03, 0x01, 0x11, 0x01, 0x05, 0x08, 0x03, 0x4B, 0x45, 0x59, 0x41, 0x31, 0x03,
    0x01, 0x01, 0x34, 0x01, 0x00, 0x05, 0x05, 0x23, 0x72, 0x6F, 0x6F, 0x74, 0x31, 0x0A, 0x03, 0x01,
    0x02, 0x01, 0x05, 0x08, 0x03, 0x4B, 0x45, 0x59, 0x32, 0x06, 0x03, 0x01, 0x06, 0x02, 0x01, 0x01,
    0x32, 0x06, 0x03, 0x01, 0x0B, 0x02, 0x01, 0x01, 0x32, 0x06, 0x03, 0x01, 0x0E, 0x02, 0x01, 0x01,
    0x41, 0x0E, 0x03, 0x01, 0x02, 0x34, 0x01, 0x01, 0x32, 0x06, 0x03, 0x01, 0x03, 0x02, 0x01, 0x02,
    0x41, 0x0E, 0x03, 0x01, 0x03, 0x34, 0x01, 0x02, 0x32, 0x06, 0x03, 0x01, 0x04, 0x02, 0x01, 0x03,
    0x41, 0x0E, 0x03, 0x01, 0x04, 0x34, 0x01, 0x03, 0x32, 0x06, 0x03, 0x01, 0x05, 0x02, 0x01, 0x04,
    0x41, 0x0F, 0x03, 0x01, 0x05, 0x34, 0x01, 0x04, 0x05, 0x07, 0x23, 0x61, 0x6E, 0x63, 0x68, 0x6F,
    0x72, 0x41, 0x12, 0x03, 0x01, 0x06, 0x34, 0x01, 0x01, 0x31, 0x0A, 0x03, 0x01, 0x07, 0x01, 0x05,
    0x08, 0x03, 0x4B, 0x45, 0x59, 0x41, 0x0E, 0x03, 0x01, 0x07, 0x34, 0x01, 0x06, 0x32, 0x06, 0x03,
    0x01, 0x08, 0x02, 0x01, 0x02, 0x41, 0x0E, 0x03, 0x01, 0x08, 0x34, 0x01, 0x07, 0x32, 0x06, 0x03,
    0x01, 0x09, 0x02, 0x01, 0x03, 0x41, 0x0E, 0x03, 0x01, 0x09, 0x34, 0x01, 0x08, 0x32, 0x06, 0x03,
    0x01, 0x0A, 0x02, 0x01, 0x04, 0x41, 0x17, 0x03, 0x01, 0x0A, 0x34, 0x01, 0x09, 0x05, 0x0C, 0x23,
    0x61, 0x75, 0x74, 0x68, 0x6F, 0x72, 0x5F, 0x63, 0x65, 0x72, 0x74, 0x33, 0x01, 0x05, 0x41, 0x0E,
    0x03, 0x01, 0x0B, 0x34, 0x01, 0x01, 0x32, 0x06, 0x03, 0x01, 0x0C, 0x02, 0x01, 0x05, 0x41, 0x0E,
    0x03, 0x01, 0x0C, 0x34, 0x01, 0x0B, 0x32, 0x06, 0x03, 0x01, 0x0D, 0x02, 0x01, 0x06, 0x41, 0x10,
    0x03, 0x01, 0x0D, 0x34, 0x01, 0x0C, 0x05, 0x05, 0x23, 0x64, 0x61, 0x74, 0x61, 0x33, 0x01, 0x10,
    0x41, 0x12, 0x03, 0x01, 0x0E, 0x34, 0x01, 0x01, 0x31, 0x0A, 0x03, 0x01, 0x0F, 0x01, 0x05, 0x08,
    0x03, 0x4B, 0x45, 0x59, 0x41, 0x0E, 0x03, 0x01, 0x0F, 0x34, 0x01, 0x0E, 0x32, 0x06, 0x03, 0x01,
    0x10, 0x02, 0x01, 0x07, 0x41, 0x13, 0x03, 0x01, 0x10, 0x34, 0x01, 0x0F, 0x05, 0x0B, 0x23, 0x61,
    0x75, 0x74, 0x68, 0x6F, 0x72, 0x5F, 0x6B, 0x65, 0x79, 0x41, 0x0E, 0x03, 0x01, 0x11, 0x34, 0x01,
    0x00, 0x32, 0x06, 0x03, 0x01, 0x12, 0x02, 0x01, 0x02, 0x41, 0x0E, 0x03, 0x01, 0x12, 0x34, 0x01,
    0x11, 0x32, 0x06, 0x03, 0x01, 0x13, 0x02, 0x01, 0x03, 0x41, 0x0E, 0x03, 0x01, 0x13, 0x34, 0x01,
    0x12, 0x32, 0x06, 0x03, 0x01, 0x14, 0x02, 0x01, 0x04, 0x41, 0x0C, 0x03, 0x01, 0x14, 0x34, 0x01,
    0x13, 0x05, 0x04, 0x23, 0x4B, 0x45, 0x59, 0x42, 0x0B, 0x02, 0x01, 0x01, 0x05, 0x06, 0x61, 0x75,
    0x74, 0x68, 0x6F, 0x72,
  };
  tlv::bstring_view buf(buffer, sizeof(buffer));

  auto model = lvs::LvsModel::Parse(buf);
  BOOST_CHECK(model.has_value());

  auto checker = lvs::Checker(*model, {});
  ndn::Name pkt_name("/example/testApp/randomData/v=1648365523687");
  ndn::Name key_name("/example/testApp/KEY/%3E%8C%1F%0EaB3Z");
  BOOST_CHECK(checker.check(pkt_name, key_name));
}

BOOST_AUTO_TEST_SUITE_END() // TestLvs

} // namespace tests