// Network Recovery Planner - identities and integrity digests.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "nrp/ids.hpp"

#include <array>
#include <cstdio>

#include "nrp/result.hpp"
#include "nrp/version.hpp"

namespace nrp {
namespace {

std::uint64_t mix64(std::uint64_t value) noexcept {
  value += 0x9E3779B97F4A7C15ull;
  value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ull;
  value = (value ^ (value >> 27)) * 0x94D049BB133111EBull;
  return value ^ (value >> 31);
}

std::uint64_t rotl(std::uint64_t value, unsigned shift) noexcept {
  return (value << shift) | (value >> (64u - shift));
}

}  // namespace

const char* to_string(StatusCode code) noexcept {
  switch (code) {
    case StatusCode::OK: return "OK";
    case StatusCode::INVALID_ARGUMENT: return "INVALID_ARGUMENT";
    case StatusCode::OUT_OF_RANGE: return "OUT_OF_RANGE";
    case StatusCode::CORRUPT: return "CORRUPT";
    case StatusCode::UNSUPPORTED: return "UNSUPPORTED";
    case StatusCode::IO_ERROR: return "IO_ERROR";
    case StatusCode::EXHAUSTED: return "EXHAUSTED";
    case StatusCode::NOT_FOUND: return "NOT_FOUND";
    case StatusCode::STATE_MISMATCH: return "STATE_MISMATCH";
    case StatusCode::PROTOCOL_ERROR: return "PROTOCOL_ERROR";
    case StatusCode::CLOSED: return "CLOSED";
    case StatusCode::CONFLICT: return "CONFLICT";
  }
  return "UNRECOGNISED_STATUS";
}

Digest digest_of(const std::uint8_t* data, std::size_t size) {
  // Two independent 64 bit accumulators over the same bytes. This is an
  // integrity digest for corruption detection, not a cryptographic hash.
  std::uint64_t fnv = 0xCBF29CE484222325ull;
  std::uint64_t poly = 0x6A09E667F3BCC909ull;
  for (std::size_t i = 0; i < size; ++i) {
    const std::uint64_t byte = data[i];
    fnv ^= byte;
    fnv *= 0x100000001B3ull;
    poly = rotl(poly, 7) ^ (byte * 0x9E3779B97F4A7C15ull + 0xBF58476D1CE4E5B9ull);
    poly += 0x94D049BB133111EBull;
  }
  Digest digest;
  digest.lo = mix64(fnv ^ (static_cast<std::uint64_t>(size) * 0x100000001B3ull));
  digest.hi = mix64(poly ^ (static_cast<std::uint64_t>(size) + 0x9E3779B97F4A7C15ull));
  return digest;
}

Digest digest_of(const std::vector<std::uint8_t>& bytes) {
  return digest_of(bytes.data(), bytes.size());
}

std::string Digest::hex() const {
  std::array<char, 33> buffer{};
  std::snprintf(buffer.data(), buffer.size(), "%016llx%016llx",
                static_cast<unsigned long long>(hi),
                static_cast<unsigned long long>(lo));
  return std::string(buffer.data(), 32);
}

std::string version_string() {
  return std::to_string(kVersionMajor) + "." + std::to_string(kVersionMinor) + "." +
         std::to_string(kVersionPatch);
}

std::string version_string_with_build() {
  return version_string() + " (domain format " + std::to_string(kDomainFormatVersion) +
         ", persistence format " + std::to_string(kPersistenceFormatVersion) + ", protocol " +
         std::to_string(kProtocolVersion) + ")";
}

const char* to_string(SubjectKind kind) noexcept {
  switch (kind) {
    case SubjectKind::NONE: return "NONE";
    case SubjectKind::NODE: return "NODE";
    case SubjectKind::LINK: return "LINK";
    case SubjectKind::SERVICE: return "SERVICE";
    case SubjectKind::RESOURCE: return "RESOURCE";
    case SubjectKind::ACTION: return "ACTION";
    case SubjectKind::FABRIC: return "FABRIC";
  }
  return "UNRECOGNISED_SUBJECT_KIND";
}

bool is_valid(SubjectKind kind) noexcept {
  switch (kind) {
    case SubjectKind::NONE:
    case SubjectKind::NODE:
    case SubjectKind::LINK:
    case SubjectKind::SERVICE:
    case SubjectKind::RESOURCE:
    case SubjectKind::ACTION:
    case SubjectKind::FABRIC:
      return true;
  }
  return false;
}

Subject subject_of(NodeId id) { return Subject{SubjectKind::NODE, id.value()}; }
Subject subject_of(LinkId id) { return Subject{SubjectKind::LINK, id.value()}; }
Subject subject_of(ServiceId id) { return Subject{SubjectKind::SERVICE, id.value()}; }
Subject subject_of(ResourceId id) { return Subject{SubjectKind::RESOURCE, id.value()}; }
Subject subject_of(ActionId id) { return Subject{SubjectKind::ACTION, id.value()}; }

std::string describe(const Subject& subject) {
  return std::string(to_string(subject.kind)) + ":" + std::to_string(subject.id);
}

}  // namespace nrp
