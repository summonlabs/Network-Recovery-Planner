// Network Recovery Planner - version and build identity.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef NRP_VERSION_HPP
#define NRP_VERSION_HPP

#include <cstdint>
#include <string>

namespace nrp {

inline constexpr std::uint32_t kVersionMajor = 1;
inline constexpr std::uint32_t kVersionMinor = 0;
inline constexpr std::uint32_t kVersionPatch = 0;

/// Durable/wire format version of the plan and domain canonical encodings.
inline constexpr std::uint32_t kDomainFormatVersion = 1;
/// Durable format version of the persistence journal/snapshot envelope.
inline constexpr std::uint32_t kPersistenceFormatVersion = 1;
/// Wire format version of the framed transport protocol.
inline constexpr std::uint16_t kProtocolVersion = 1;

std::string version_string();
std::string version_string_with_build();

}  // namespace nrp

#endif  // NRP_VERSION_HPP
