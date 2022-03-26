#pragma once

#include <tuple>
#include <optional>
#include <cstdint>
#include <type_traits>
#include <bit>
#include <string_view>
#include <vector>

#if defined(__cpp_concepts) && defined(__GNUC__) && (__GNUC__ >= 10)
#include <concepts>
#define WITH_CONCEPTS 1
#else
#define WITH_CONCEPTS 0
#endif

namespace tlv {

// The result of parsing. Theoretically, it should be Optional<Tuple<T, size_t>>.
// This definition is for coding convenience.
template<typename T>
using ParseResult = std::tuple<std::optional<T>, size_t>;

using bstring_view = std::basic_string_view<std::uint8_t>;
using NameComponent = bstring_view;
using Name = std::vector<bstring_view>;

#if WITH_CONCEPTS

template<typename T>
concept ByteString =
  requires(T wire, size_t pos, size_t count) {
    { wire.size() } -> std::convertible_to<size_t>;
    { wire[pos] } -> std::convertible_to<std::uint8_t>;
    { &wire[pos] } -> std::convertible_to<const std::uint8_t*>;
    { wire.substr(pos, count - pos) } -> std::convertible_to<T>;
  };

template<typename T, typename B>
concept Parsable =
  requires(T e, const B& wire) {
    ByteString<B>;
    T::Parse(wire);
  };

template<typename T, typename E, typename B>
concept Parses =
  requires(T value, const B& wire) {
    Parsable<E, B>;
    { E::Parse(wire) } -> std::convertible_to<ParseResult<T>>;
  };

#define REQUIRES_PARSES(t, e, b) requires Parses<t, e, b>
#define REQUIRES_PARSABLE(e, b) requires Parsable<e, b>
#define INTEGRAL std::integral

#else
#define ByteString typename
#define REQUIRES_PARSES(t, e, b)
#define REQUIRES_PARSABLE(e, b)
#define INTEGRAL typename
#endif


// Encoding of integers in BigEndian
namespace big_endian {
  template<INTEGRAL Int>
  inline Int Read(const std::uint8_t* buf);

  template<>
  inline uint8_t Read<uint8_t>(const std::uint8_t buf[]){
    return *reinterpret_cast<const uint8_t*>(buf);
  }

  template<>
  inline uint16_t Read<uint16_t>(const std::uint8_t buf[]){
    // std::byteswap is C++23
    if constexpr (std::endian::native == std::endian::little) {
      return __builtin_bswap16(*reinterpret_cast<const uint16_t*>(buf));
    } else {
      return *reinterpret_cast<const uint16_t*>(buf);
    }
  }

  template<>
  inline uint32_t Read<uint32_t>(const std::uint8_t buf[]){
    if constexpr (std::endian::native == std::endian::little) {
      return __builtin_bswap32(*reinterpret_cast<const uint32_t*>(buf));
    } else {
      return *reinterpret_cast<const uint32_t*>(buf);
    }
  }

  template<>
  inline uint64_t Read<uint64_t>(const std::uint8_t buf[]){
    if constexpr (std::endian::native == std::endian::little) {
      return __builtin_bswap64(*reinterpret_cast<const uint64_t*>(buf));
    } else {
      return *reinterpret_cast<const uint64_t*>(buf);
    }
  }
} // namespace big_endian

// TlvConst is a TLV type number constant, known at compiling time.
template<uint64_t num>
struct TlvConst {
  TlvConst() = default;

  template<ByteString B>
  static inline ParseResult<uint64_t> Parse(const B& wire) {
    if constexpr (num <= 0xfc){
      if (wire.size() >= 1 && wire[0] == uint8_t(num)){
        return {num, 1};
      }
    } else if constexpr (num <= 0xffff){
      if (wire.size() >= 3 && wire[0] == 0xfd && big_endian::Read<uint16_t>(&wire[1]) == uint16_t(num)){
        return {num, 3};
      }
    } else if constexpr (num <= 0xffffffff){
      if (wire.size() >= 5 && wire[0] == 0xfe && big_endian::Read<uint32_t>(&wire[1]) == uint32_t(num)){
        return {num, 5};
      }
    } else {
      if (wire.size() >= 9 && wire[0] == 0xff && big_endian::Read<uint64_t>(&wire[1]) == num){
        return {num, 9};
      }
    }
    return {std::nullopt, 0};
  }
};

// TlvVar is a TLV type number variable.
struct TlvVar {
  template<ByteString B>
  static inline ParseResult<uint64_t> Parse(const B& wire) {
    if (wire.size() >= 1) {
      uint8_t val = wire[0];
      if (val <= 0xfc){
        return {uint64_t(val), 1};
      } else if (val == 0xfd){
        if (wire.size() >= 3){
          return {uint64_t(big_endian::Read<uint16_t>(&wire[1])), 3};
        }
      } else if (val == 0xfe){
        if (wire.size() >= 5){
          return {uint64_t(big_endian::Read<uint32_t>(&wire[1])), 5};
        }
      } else if (val == 0xff){
        if (wire.size() >= 9){
          return {big_endian::Read<uint64_t>(&wire[1]), 9};
        }
      }
    }
    return {std::nullopt, 0};
  }
};

// NaturalNumber is a natural number, without type and length.
struct NaturalNumber {
  template<ByteString B>
  static inline ParseResult<uint64_t> Parse(const B& wire) {
    // Require exact size
    if (wire.size() == 1){
      return {uint64_t(wire[0]), 1};
    } else if (wire.size() == 2){
      return {uint64_t(big_endian::Read<uint16_t>(wire.begin())), 2};
    } else if (wire.size() == 4){
      return {uint64_t(big_endian::Read<uint32_t>(wire.begin())), 4};
    } else if (wire.size() == 8){
      return {big_endian::Read<uint64_t>(wire.begin()), 8};
    }
    return {std::nullopt, 0};
  }
};

// Unit is void type.
// This is used to construct a bool field.
struct Unit {
  template<ByteString B>
  static inline ParseResult<bool> Parse(const B& wire) {
    return {true, 0};
  }
};

// BinString works for std::string, std::vector<std::uint8_t> and std::array<std::uint8_t, N>.
template<typename Vector>
struct BinString {
  template<ByteString B>
  static inline ParseResult<Vector> Parse(const B& wire) {
    // Require exact size
    return {wire, wire.size()};
  }
};

// NameComponentEncoder is the same as ByteString,
// except that its Parse() reads exactly one TlvBlock instead of greedy.
struct NameComponentEncoder {
  template<ByteString B>
  static inline ParseResult<B> Parse(const B& wire) {
    // Read a TLV block
    size_t pos = 0;
    const auto& [typ, tsiz] = TlvVar::Parse(wire);
    pos += tsiz;
    if(!typ){
      return {std::nullopt, 0};
    }
    const auto& [length, lsiz] = TlvVar::Parse(wire.substr(pos, wire.size() - pos));
    pos += lsiz;
    size_t total_size = pos + length.value();
    if(!length || total_size > wire.size()){
      return {std::nullopt, 0};
    }

    return {wire, total_size};
  }
};

// Sequence is a sequence of any type, i.e. std::vector<T>
// Elements will be encoded in order.
// To make users' life easier, here we separate T and Encodable,
// so users can define std::vector<unit64_t> instead of std::vector<NaturalNumber>.
// But they are fundamentally the same type.
template<typename T, typename E>
struct Sequence {
  std::vector<E> encodables;
  size_t length;
  
  inline Sequence(const std::vector<T>& values):length(0){
    encodables.reserve(values.size());
    for(const auto& v: values) {
      encodables.push_back(Encodable(v));
      length += encodables.back().EncodeSize();
    }
  }

  template<ByteString B>
  static inline ParseResult<std::vector<T>> Parse(const B& wire) REQUIRES_PARSES(T, E, B) {
    // This does a greedy parsing.
    // T must be able to handle its own size
    std::vector<T> ret;
    size_t pos = 0;
    while(pos < wire.size()){
      const auto& [val, siz] = E::Parse(wire.substr(pos, wire.size() - pos));
      if(val){
        ret.push_back(std::move(val.value()));
        pos += siz;
      } else {
        break;
      }
    }
    return {ret, pos};
  }
};

// TlvBlock encapsulate an encodable into a block with type and length.
template<uint64_t typeNum, typename T, typename E>
struct TlvBlock {
  template<ByteString B>
  static inline ParseResult<T> Parse(const B& wire) REQUIRES_PARSES(T, E, B) {
    size_t pos = 0;
    const auto& [typ, tsiz] = TlvConst<typeNum>::Parse(wire);
    pos += tsiz;
    if(!typ){
      return {std::nullopt, 0};
    }
    const auto& [length, lsiz] = TlvVar::Parse(wire.substr(pos, wire.size() - pos));
    pos += lsiz;
    if(!length || pos + length.value() > wire.size()){
      return {std::nullopt, 0};
    }
    const auto& [value, vsiz] = E::Parse(wire.substr(pos, length.value()));
    pos += length.value();
    if(!value){
      return {std::nullopt, 0};
    }
    return {value, pos};
  }
};

// OptionalBlock is an optional TLV Block.
template<uint64_t typeNum, typename T, typename E>
struct OptionalBlock {
  std::optional<E> encodable;
  size_t length;
  inline OptionalBlock(const std::optional<T>& value):encodable(value),length(0){
    if(encodable.has_value()){
      length = encodable.value().EncodeSize();
    }
  }
  template<ByteString B>
  static inline ParseResult<std::optional<T>> Parse(const B& wire) REQUIRES_PARSES(T, E, B) {
    const auto& [ret, len] = TlvBlock<typeNum, T, E>::Parse(wire);
    if(ret){
      return {ret, len};
    } else {
      return {std::make_optional<std::optional<T>>(std::nullopt), 0};
    }
  }
};

// Boolean is a bool such as MustBeFresh.
// Boolean = OptionalBlock<Unit>
template<uint64_t typeNum>
struct Boolean {
  template<ByteString B>
  static inline ParseResult<bool> Parse(const B& wire) {
    const auto& [ret, len] = OptionalBlock<typeNum, Unit, Unit>::Parse(wire);
    if(!ret.has_value()){
      return {false, 0};
    } else {
      return {true, len};
    }
  }
};

// Field wraps an encodable into a field of a struct or class.
// Model is the class of TLV model, i.e. the struct holding this field.
// Encodable is the class of original encodable, typically a TlvBlock or OptionalBlock.
// Offset is the offset to the field.
// For example, to initialize Encodable(m.a), we need to write
//   StructField<Model, Encodable, &Model::a>
template<typename Model, typename E, auto offset>
struct Field {
  E encodable;
  inline Field(const Model& model):encodable(model.*offset){}

  template<typename T>
  static inline void replace(Model& model, std::optional<T> value){
    if(value.has_value()){
      (model.*offset).emplace(*value);
    } else {
      (model.*offset) = std::nullopt;
    }
  }

  template<typename T>
  static inline void replace(Model& model, T&& value){
    (model.*offset) = std::move(value);
  }

  // Field itself is not an Encodable, so no need to implement Parse()
  // The value is assigned to the specified model, so only length is returned
  // This template version handles std::optional
  template<ByteString B>
  static inline std::optional<size_t> ParseField(const B& wire, Model& model) REQUIRES_PARSABLE(E, B) {
    auto [val, len] = E::Parse(wire);
    if(val.has_value()){
      // Assign to the field if success
      // Optional field returns a make_optional(std::null_opt) when missing,
      // so it will be treated as success.
      replace(model, val.value());
      return len;
    } else {
      // Failed to parse the field
      // This leads to failing to parse the whole struct
      return std::nullopt;
    }
  }
};

// Struct represents a struct that is encodable.
// Encoder parameters specify the encodable fields of this struct/class.
// They will be called in order.
// The only parameter passed to initialize field encoders are the instance of the struct/class.
template<typename Model, typename ...Fields>
struct Struct {
  // Store the encodable instances of fields.
  std::tuple<Fields...> fields;

  // Use the instance to initialize the field encoders.
  inline Struct(const Model& model):fields(std::make_tuple(Fields(model)...)){}

  // Struct is an Encodable. It must implement the standard Parse()
  // So its field parsing function is renamed as ParseField
  template<typename B, typename Field>
  static inline std::optional<size_t>
  ParseField(const B& wire, Model& model) {
    return Field::ParseField(wire, model);
  }

  template<typename B, typename Field, typename Field2, typename ...MoreFields>
  static inline std::optional<size_t>
  ParseField(const B& wire, Model& model) {
    // TODO: Handle unrecognized fields
    auto pos = Field::ParseField(wire, model);
    if(!pos.has_value()){
      return std::nullopt;
    }
    auto rest = ParseField<B, Field2, MoreFields...>(wire.substr(pos.value(), wire.size() - pos.value()), model);
    if(!rest.has_value()){
      return std::nullopt;
    }
    return pos.value() + rest.value();
  }

  template<typename B>
  static inline ParseResult<Model> Parse(const B& wire) {
    Model ret;
    std::optional<size_t> pos = ParseField<B, Fields...>(wire, ret);
    if(pos.has_value()){
      return {std::make_optional<Model>(std::move(ret)), pos.value()};
    } else {
      return {std::nullopt, 0};
    }
  }
};

template<uint64_t typeNum, typename Model, uint64_t Model::* offset>
using NaturalField = Field<Model, TlvBlock<typeNum, uint64_t, NaturalNumber>, offset>;

template<uint64_t typeNum, typename Model, std::optional<uint64_t> Model::* offset>
using NaturalFieldOpt = Field<Model, OptionalBlock<typeNum, uint64_t, NaturalNumber>, offset>;

template<uint64_t typeNum, typename Model, typename Vector, Vector Model::* offset>
using BytesField = Field<Model, TlvBlock<typeNum, Vector, BinString<Vector>>, offset>;

template<uint64_t typeNum, typename Model, typename Vector, std::optional<Vector> Model::* offset>
using BytesFieldOpt = Field<Model, OptionalBlock<typeNum, Vector, BinString<Vector>>, offset>;

template<uint64_t typeNum, typename Model, bool Model::* offset>
using BoolField = Field<Model, Boolean<typeNum>, offset>;

// StructField is a field whose type is another encodable struct.
// Every struct is required to have its encodable type defined as Model::Parsable.
template<uint64_t typeNum, typename Model,
         typename StructType, StructType Model::* offset>
using StructField = Field<Model,
                          TlvBlock<typeNum, StructType, typename StructType::Parsable>, offset>;

template<uint64_t typeNum, typename Model,
         typename StructType, std::optional<StructType> Model::* offset>
using StructFieldOpt = Field<Model,
                             OptionalBlock<typeNum, StructType, typename StructType::Parsable>, offset>;

using EncodableName = Sequence<bstring_view, NameComponentEncoder>;

template<uint64_t typeNum, typename Model, Name Model::* offset>
using NameField = Field<Model, TlvBlock<typeNum, Name, EncodableName>, offset>;

template<uint64_t typeNum, typename Model, NameComponent Model::* offset>
using NameComponentField = Field<Model,
                                 TlvBlock<typeNum, NameComponent, BinString<NameComponent>>,
                                 offset>;

template<uint64_t typeNum, typename Model, std::optional<NameComponent> Model::* offset>
using NameComponentFieldOpt = Field<Model,
                                    OptionalBlock<typeNum, NameComponent, BinString<NameComponent>>,
                                    offset>;

} // namespace tlv
