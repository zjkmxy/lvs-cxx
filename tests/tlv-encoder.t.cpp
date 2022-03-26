#include <boost-test.hpp>
#include <cstddef>
#include <optional>

#include "tlv-encoder.hpp"

namespace tests {

BOOST_AUTO_TEST_SUITE(TestTlv)

BOOST_AUTO_TEST_CASE(BigEndian)
{
  std::uint8_t buf[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

  uint8_t u8_val = tlv::big_endian::Read<uint8_t>(buf);
  BOOST_CHECK_EQUAL(u8_val, 0x01);

  uint16_t u16_val = tlv::big_endian::Read<uint16_t>(buf);
  BOOST_CHECK_EQUAL(u16_val, 0x0102);

  uint32_t u32_val = tlv::big_endian::Read<uint32_t>(buf);
  BOOST_CHECK_EQUAL(u32_val, 0x01020304);

  uint64_t u64_val = tlv::big_endian::Read<uint64_t>(buf);
  BOOST_CHECK_EQUAL(u64_val, 0x0102030405060708ull);
}

BOOST_AUTO_TEST_CASE(Encoding1)
{
  struct MetaInfo {
    std::optional<uint64_t> contentType;
    std::optional<uint64_t> freshnessPeriod;
    std::optional<tlv::NameComponent> finalBlockId;
    
    using Parsable = tlv::Struct<MetaInfo,
      tlv::NaturalFieldOpt<0x18, MetaInfo, &MetaInfo::contentType>,
      tlv::NaturalFieldOpt<0x19, MetaInfo, &MetaInfo::freshnessPeriod>,
      tlv::NameComponentFieldOpt<0x1a, MetaInfo, &MetaInfo::finalBlockId>>;
  };

  std::uint8_t buffer[] = {0x18, 0x01, 0x01, 0x19, 0x02, 0x0f, 0xa0, 0x1a, 0x05, 0x08, 0x03, 'n', 'd', 'n'};
  tlv::bstring_view buf(buffer, sizeof(buffer));
  const auto& [metainfo, wiresize] = MetaInfo::Parsable::Parse(buf);
  BOOST_CHECK_EQUAL(wiresize, sizeof(buffer));
  BOOST_CHECK(metainfo.has_value());
  BOOST_CHECK_EQUAL(metainfo->contentType.value(), 0x01);
  BOOST_CHECK_EQUAL(metainfo->freshnessPeriod.value(), 0x0fa0);
  BOOST_CHECK(metainfo->finalBlockId.value() == tlv::bstring_view(buffer + 9, 5));
}

BOOST_AUTO_TEST_SUITE_END() // TestTlv

} // namespace tests