// Network Recovery Planner - deterministic canonical serialisation.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef NRP_CANONICAL_HPP
#define NRP_CANONICAL_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "nrp/result.hpp"

namespace nrp {

/// Append-only canonical writer.
///
/// Encoding rules (fixed for format version 1):
///   * every integer is little-endian, fixed width, two's complement for signed;
///   * strings and byte strings are length-prefixed with a u32 length and carry
///     no terminator;
///   * containers are length-prefixed with a u32 element count;
///   * floating point is never used by any durable or wire encoding.
/// The same rules are used for digests, durable records and wire payloads, so a
/// digest over an encoding is exactly the identity of the encoded value.
class CanonicalWriter {
 public:
  void u8(std::uint8_t value);
  void u16(std::uint16_t value);
  void u32(std::uint32_t value);
  void u64(std::uint64_t value);
  void i64(std::int64_t value);
  void boolean(bool value);
  void bytes(const std::uint8_t* data, std::size_t size);
  void bytes(const std::vector<std::uint8_t>& data);
  void str(std::string_view value);

  const std::vector<std::uint8_t>& buffer() const noexcept { return buffer_; }
  std::vector<std::uint8_t> take() { return std::move(buffer_); }
  std::size_t size() const noexcept { return buffer_.size(); }
  void clear() { buffer_.clear(); }

 private:
  std::vector<std::uint8_t> buffer_;
};

/// Bounds-checked canonical reader with sticky failure.
///
/// After the first structural error every subsequent read returns zero and
/// ok() stays false, so a decoder can never observe a partially valid value.
class CanonicalReader {
 public:
  CanonicalReader(const std::uint8_t* data, std::size_t size)
      : data_(data), size_(size) {}
  explicit CanonicalReader(const std::vector<std::uint8_t>& data)
      : data_(data.data()), size_(data.size()) {}

  bool ok() const noexcept { return error_.ok(); }
  const Status& status() const noexcept { return error_; }
  std::size_t remaining() const noexcept { return size_ - offset_; }
  std::size_t offset() const noexcept { return offset_; }
  bool at_end() const noexcept { return offset_ == size_; }

  std::uint8_t u8();
  std::uint16_t u16();
  std::uint32_t u32();
  std::uint64_t u64();
  std::int64_t i64();
  bool boolean();
  std::vector<std::uint8_t> bytes(std::size_t max_length);
  std::vector<std::uint8_t> blob(std::uint32_t declared_length);
  std::string str(std::size_t max_length);

  /// Rejects any trailing bytes. Decoding is total: a well formed value either
  /// consumes the frame exactly or the decode fails.
  Status require_end();

  void fail(StatusCode code, std::string message);

  /// Reads an enum valued field and validates it against the declared domain.
  template <class E>
  E enum_value(std::uint8_t max_exclusive, const char* what) {
    const std::uint8_t raw = u8();
    if (!ok()) return static_cast<E>(0);
    if (raw >= max_exclusive) {
      fail(StatusCode::PROTOCOL_ERROR,
           std::string("enum out of domain for ") + what + ": " + std::to_string(raw));
      return static_cast<E>(0);
    }
    return static_cast<E>(raw);
  }

  /// Reads a u32 count that must stay within a caller supplied bound.
  std::uint32_t bounded_count(std::uint32_t max_count, const char* what);

 private:
  bool need(std::size_t count);

  const std::uint8_t* data_ = nullptr;
  std::size_t size_ = 0;
  std::size_t offset_ = 0;
  Status error_;
};

/// Checked arithmetic helpers. Overflow is a first class, reported failure;
/// no accumulation in this runtime wraps around silently.
bool add_overflow(std::uint64_t a, std::uint64_t b, std::uint64_t* out) noexcept;
bool mul_overflow(std::uint64_t a, std::uint64_t b, std::uint64_t* out) noexcept;

}  // namespace nrp

#endif  // NRP_CANONICAL_HPP
