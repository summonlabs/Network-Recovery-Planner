// Network Recovery Planner - deterministic canonical serialisation.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "nrp/canonical.hpp"

#include <cstring>

namespace nrp {

void CanonicalWriter::u8(std::uint8_t value) { buffer_.push_back(value); }

void CanonicalWriter::u16(std::uint16_t value) {
  buffer_.push_back(static_cast<std::uint8_t>(value & 0xFFu));
  buffer_.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
}

void CanonicalWriter::u32(std::uint32_t value) {
  for (int shift = 0; shift < 32; shift += 8) {
    buffer_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
  }
}

void CanonicalWriter::u64(std::uint64_t value) {
  for (int shift = 0; shift < 64; shift += 8) {
    buffer_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
  }
}

void CanonicalWriter::i64(std::int64_t value) {
  u64(static_cast<std::uint64_t>(value));
}

void CanonicalWriter::boolean(bool value) { u8(value ? 1u : 0u); }

void CanonicalWriter::bytes(const std::uint8_t* data, std::size_t size) {
  u32(static_cast<std::uint32_t>(size));
  buffer_.insert(buffer_.end(), data, data + size);
}

void CanonicalWriter::bytes(const std::vector<std::uint8_t>& data) {
  bytes(data.data(), data.size());
}

void CanonicalWriter::str(std::string_view value) {
  u32(static_cast<std::uint32_t>(value.size()));
  buffer_.insert(buffer_.end(), value.begin(), value.end());
}

bool CanonicalReader::need(std::size_t count) {
  if (!error_.ok()) return false;
  if (count > size_ - offset_) {
    fail(StatusCode::PROTOCOL_ERROR, "canonical encoding truncated");
    return false;
  }
  return true;
}

void CanonicalReader::fail(StatusCode code, std::string message) {
  if (error_.ok()) {
    error_ = Status::error(code, std::move(message));
  }
}

std::uint8_t CanonicalReader::u8() {
  if (!need(1)) return 0;
  return data_[offset_++];
}

std::uint16_t CanonicalReader::u16() {
  if (!need(2)) return 0;
  const std::uint16_t value = static_cast<std::uint16_t>(data_[offset_]) |
                              static_cast<std::uint16_t>(data_[offset_ + 1] << 8);
  offset_ += 2;
  return value;
}

std::uint32_t CanonicalReader::u32() {
  if (!need(4)) return 0;
  std::uint32_t value = 0;
  for (int index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(data_[offset_ + static_cast<std::size_t>(index)]) << (8 * index);
  }
  offset_ += 4;
  return value;
}

std::uint64_t CanonicalReader::u64() {
  if (!need(8)) return 0;
  std::uint64_t value = 0;
  for (int index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(data_[offset_ + static_cast<std::size_t>(index)]) << (8 * index);
  }
  offset_ += 8;
  return value;
}

std::int64_t CanonicalReader::i64() { return static_cast<std::int64_t>(u64()); }

bool CanonicalReader::boolean() {
  const std::uint8_t raw = u8();
  if (!ok()) return false;
  if (raw > 1u) {
    fail(StatusCode::PROTOCOL_ERROR, "boolean out of domain");
    return false;
  }
  return raw == 1u;
}

std::uint32_t CanonicalReader::bounded_count(std::uint32_t max_count, const char* what) {
  const std::uint32_t count = u32();
  if (!ok()) return 0;
  if (count > max_count) {
    fail(StatusCode::OUT_OF_RANGE,
         std::string("declared count for ") + what + " exceeds the model limit: " +
             std::to_string(count) + " > " + std::to_string(max_count));
    return 0;
  }
  return count;
}

std::vector<std::uint8_t> CanonicalReader::blob(std::uint32_t declared_length) {
  const std::uint32_t length = u32();
  if (!ok()) return {};
  if (length != declared_length) {
    fail(StatusCode::PROTOCOL_ERROR,
         "declared blob length mismatch: " + std::to_string(length) + " != " +
             std::to_string(declared_length));
    return {};
  }
  return bytes(length);
}

std::vector<std::uint8_t> CanonicalReader::bytes(std::size_t max_length) {
  const std::uint32_t length = u32();
  if (!ok()) return {};
  if (length > max_length) {
    fail(StatusCode::OUT_OF_RANGE, "declared byte length exceeds the bound");
    return {};
  }
  if (!need(length)) return {};
  std::vector<std::uint8_t> out(data_ + offset_, data_ + offset_ + length);
  offset_ += length;
  return out;
}

std::string CanonicalReader::str(std::size_t max_length) {
  const std::uint32_t length = u32();
  if (!ok()) return {};
  if (length > max_length) {
    fail(StatusCode::OUT_OF_RANGE, "declared string length exceeds the bound");
    return {};
  }
  if (!need(length)) return {};
  std::string out(reinterpret_cast<const char*>(data_ + offset_), length);
  offset_ += length;
  return out;
}

Status CanonicalReader::require_end() {
  if (!error_.ok()) return error_;
  if (offset_ != size_) {
    return Status::error(StatusCode::PROTOCOL_ERROR,
                         "trailing bytes after canonical value: " + std::to_string(size_ - offset_));
  }
  return Status::success();
}

bool add_overflow(std::uint64_t a, std::uint64_t b, std::uint64_t* out) noexcept {
  if (a > UINT64_MAX - b) return true;
  *out = a + b;
  return false;
}

bool mul_overflow(std::uint64_t a, std::uint64_t b, std::uint64_t* out) noexcept {
  if (a != 0 && b > UINT64_MAX / a) return true;
  *out = a * b;
  return false;
}

}  // namespace nrp
