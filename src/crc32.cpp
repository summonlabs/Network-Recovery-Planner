// Network Recovery Planner - internal CRC-32 helper.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "detail/crc32.hpp"

namespace nrp::detail {
namespace {

struct Table {
  std::uint32_t entries[256];
  constexpr Table() : entries{} {
    for (std::uint32_t i = 0; i < 256; ++i) {
      std::uint32_t value = i;
      for (int bit = 0; bit < 8; ++bit) {
        value = (value & 1u) != 0u ? (0xEDB88320u ^ (value >> 1)) : (value >> 1);
      }
      entries[i] = value;
    }
  }
};

constexpr Table kTable{};

}  // namespace

std::uint32_t crc32(const std::uint8_t* data, std::size_t size, std::uint32_t seed) noexcept {
  std::uint32_t crc = seed ^ 0xFFFFFFFFu;
  for (std::size_t i = 0; i < size; ++i) {
    crc = kTable.entries[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
  }
  return crc ^ 0xFFFFFFFFu;
}

}  // namespace nrp::detail
