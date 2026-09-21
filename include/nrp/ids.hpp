// Network Recovery Planner - strongly typed identities and integrity digests.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef NRP_IDS_HPP
#define NRP_IDS_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace nrp {

/// Strongly typed 64-bit identity. Two identities of different tags are not
/// interchangeable: the compiler rejects mixing a NodeId with a LinkId.
template <class Tag>
class StrongId {
 public:
  constexpr StrongId() = default;

  static constexpr StrongId from_value(std::uint64_t value) {
    StrongId id;
    id.value_ = value;
    return id;
  }

  constexpr std::uint64_t value() const noexcept { return value_; }
  constexpr bool is_zero() const noexcept { return value_ == 0; }

  friend constexpr bool operator==(StrongId a, StrongId b) { return a.value_ == b.value_; }
  friend constexpr bool operator!=(StrongId a, StrongId b) { return a.value_ != b.value_; }
  friend constexpr bool operator<(StrongId a, StrongId b) { return a.value_ < b.value_; }
  friend constexpr bool operator>(StrongId a, StrongId b) { return a.value_ > b.value_; }
  friend constexpr bool operator<=(StrongId a, StrongId b) { return a.value_ <= b.value_; }
  friend constexpr bool operator>=(StrongId a, StrongId b) { return a.value_ >= b.value_; }

 private:
  std::uint64_t value_ = 0;
};

struct NodeTag;
struct LinkTag;
struct ServiceTag;
struct ResourceTag;
struct ActionTag;
struct ExclusionGroupTag;
struct EvidenceTag;
struct RequestTag;
struct PlanTag;
struct AttemptTag;
struct SessionTag;
struct AuthorityTag;
struct BootTag;
struct EpochTag;

using NodeId = StrongId<NodeTag>;
using LinkId = StrongId<LinkTag>;
using ServiceId = StrongId<ServiceTag>;
using ResourceId = StrongId<ResourceTag>;
using ActionId = StrongId<ActionTag>;
using ExclusionGroupId = StrongId<ExclusionGroupTag>;
using EvidenceId = StrongId<EvidenceTag>;
using RequestId = StrongId<RequestTag>;
using PlanId = StrongId<PlanTag>;
using AttemptId = StrongId<AttemptTag>;
using SessionId = StrongId<SessionTag>;
using AuthorityId = StrongId<AuthorityTag>;

/// Coordinator term. Advanced on every coordinator restart / leadership change.
using Epoch = StrongId<EpochTag>;
/// Process incarnation identity. Advanced on every process boot.
using BootId = StrongId<BootTag>;

/// Monotonic per-authority sequence number.
struct Sequence {
  std::uint64_t value = 0;
  friend constexpr bool operator==(Sequence a, Sequence b) { return a.value == b.value; }
  friend constexpr bool operator!=(Sequence a, Sequence b) { return a.value != b.value; }
  friend constexpr bool operator<(Sequence a, Sequence b) { return a.value < b.value; }
  friend constexpr bool operator>(Sequence a, Sequence b) { return a.value > b.value; }
  friend constexpr bool operator<=(Sequence a, Sequence b) { return a.value <= b.value; }
  friend constexpr bool operator>=(Sequence a, Sequence b) { return a.value >= b.value; }
};

/// Generation of an authority-bearing dependency. Matching identity is never
/// matching generation: a fact or grant is only usable at its exact generation.
struct Generation {
  std::uint64_t value = 0;
  friend constexpr bool operator==(Generation a, Generation b) { return a.value == b.value; }
  friend constexpr bool operator!=(Generation a, Generation b) { return a.value != b.value; }
  friend constexpr bool operator<(Generation a, Generation b) { return a.value < b.value; }
  friend constexpr bool operator>(Generation a, Generation b) { return a.value > b.value; }
  friend constexpr bool operator<=(Generation a, Generation b) { return a.value <= b.value; }
  friend constexpr bool operator>=(Generation a, Generation b) { return a.value >= b.value; }
};

/// Non-cryptographic 128-bit integrity digest used for canonical encodings,
/// persistence records and plan identity. This is a corruption detector, not a
/// security mechanism; see the trust boundary section of the README.
struct Digest {
  std::uint64_t hi = 0;
  std::uint64_t lo = 0;

  bool is_zero() const noexcept { return hi == 0 && lo == 0; }
  std::string hex() const;

  friend bool operator==(const Digest& a, const Digest& b) { return a.hi == b.hi && a.lo == b.lo; }
  friend bool operator!=(const Digest& a, const Digest& b) { return !(a == b); }
  friend bool operator<(const Digest& a, const Digest& b) {
    if (a.hi != b.hi) return a.hi < b.hi;
    return a.lo < b.lo;
  }
};

/// Computes the integrity digest of a byte range.
Digest digest_of(const std::uint8_t* data, std::size_t size);
Digest digest_of(const std::vector<std::uint8_t>& bytes);

/// Subject of an observation or constraint: a typed reference into the fabric
/// model. Modelled as (kind, id) so that it can be canonically ordered and
/// encoded without polymorphic containers.
enum class SubjectKind : std::uint8_t {
  NONE = 0,
  NODE = 1,
  LINK = 2,
  SERVICE = 3,
  RESOURCE = 4,
  ACTION = 5,
  FABRIC = 6,
};

const char* to_string(SubjectKind kind) noexcept;
/// Returns false for values outside the defined enum domain (untrusted input).
bool is_valid(SubjectKind kind) noexcept;

struct Subject {
  SubjectKind kind = SubjectKind::NONE;
  std::uint64_t id = 0;

  friend bool operator==(const Subject& a, const Subject& b) {
    return a.kind == b.kind && a.id == b.id;
  }
  friend bool operator!=(const Subject& a, const Subject& b) { return !(a == b); }
  friend bool operator<(const Subject& a, const Subject& b) {
    if (a.kind != b.kind) return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
    return a.id < b.id;
  }
};

Subject subject_of(NodeId id);
Subject subject_of(LinkId id);
Subject subject_of(ServiceId id);
Subject subject_of(ResourceId id);
Subject subject_of(ActionId id);

std::string describe(const Subject& subject);

}  // namespace nrp

#endif  // NRP_IDS_HPP
