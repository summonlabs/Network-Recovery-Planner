// Network Recovery Planner - internal CRC-32 helper (not installed).
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef NRP_DETAIL_CRC32_HPP
#define NRP_DETAIL_CRC32_HPP

#include <cstddef>
#include <cstdint>

namespace nrp::detail {

/// CRC-32 (IEEE 802.3, reflected, polynomial 0xEDB88320). Used for record and
/// frame integrity only; it is a corruption detector and not a MAC.
std::uint32_t crc32(const std::uint8_t* data, std::size_t size, std::uint32_t seed = 0) noexcept;

}  // namespace nrp::detail

#endif  // NRP_DETAIL_CRC32_HPP
