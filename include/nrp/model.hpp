// Network Recovery Planner - authority, generations, evidence and outcomes.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef NRP_MODEL_HPP
#define NRP_MODEL_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "nrp/canonical.hpp"
#include "nrp/ids.hpp"

namespace nrp {

// ---------------------------------------------------------------------------
// Evidence provenance
// ---------------------------------------------------------------------------

/// How an input was produced. Never inferred, always declared by the producer.
enum class TrustLabel : std::uint8_t {
  UNKNOWN = 0,
  REAL = 1,         // produced by the physical/adjacent system that owns the fact
  SYNTHETIC = 2,    // produced by a deterministic fixture or model
  UNSUPPORTED = 3,  // no evidence path exists on this host for this fact
};

const char* to_string(TrustLabel label) noexcept;
bool is_valid(TrustLabel label) noexcept;

// ---------------------------------------------------------------------------
// Authority
// ---------------------------------------------------------------------------

/// Authority-bearing dependency domains. A plan step may only rely on a domain
/// that is proven current at the exact generation the step binds.
enum class AuthorityDomain : std::uint8_t {
  FABRIC_STATE = 0,       // authoritative observed fabric state
  RECOVERY_ADMISSION = 1, // adjacent runtime that admits/executes repair actions
  RESOURCE_LEASE = 2,     // scarce recovery resource lease authority
  POLICY = 3,             // governing recovery policy
  EVIDENCE_INGEST = 4,    // evidence ingest/binding authority
  COUNT = 5,
};

const char* to_string(AuthorityDomain domain) noexcept;
bool is_valid(AuthorityDomain domain) noexcept;

/// Strength of a claim. The planner itself never asserts anything above
/// RECOMMENDATION; AUTHORIZATION and above belong to adjacent runtimes.
enum class AuthorityLevel : std::uint8_t {
  NONE = 0,
  OBSERVATION = 1,
  ELIGIBILITY = 2,
  RECOMMENDATION = 3,
  AUTHORIZATION = 4,
  ACKNOWLEDGEMENT = 5,
  VERIFIED_EFFECT = 6,
  COUNT = 7,
};

const char* to_string(AuthorityLevel level) noexcept;
bool is_valid(AuthorityLevel level) noexcept;

/// Admissibility of an authority binding, evaluated, never assumed.
enum class BindingState : std::uint8_t {
  CURRENT = 0,
  STALE = 1,
  UNKNOWN = 2,
  CONFLICT = 3,
  INVALID = 4,
  UNSUPPORTED = 5,
  COUNT = 6,
};

const char* to_string(BindingState state) noexcept;

struct AuthorityBinding {
  AuthorityDomain domain = AuthorityDomain::FABRIC_STATE;
  AuthorityId authority{};
  Generation required{};
  Generation granted{};
  AuthorityLevel level = AuthorityLevel::NONE;

  BindingState evaluate() const noexcept;
  friend bool operator==(const AuthorityBinding& a, const AuthorityBinding& b);
  friend bool operator<(const AuthorityBinding& a, const AuthorityBinding& b);
};

/// The authority vector bound to a request. Canonically ordered; the vector and
/// its digest are recorded in every plan so a plan can never be replayed under
/// a different authority generation.
struct AuthorityVector {
  Epoch coordinator_epoch{};
  BootId boot{};
  std::vector<AuthorityBinding> bindings;

  void canonicalise();
  const AuthorityBinding* find(AuthorityDomain domain) const noexcept;
  /// True when every present binding evaluates to CURRENT. Absent domains are
  /// absent, not current: callers must ask for the domains they need.
  bool all_current() const noexcept;
  Digest digest() const;
  void encode(CanonicalWriter& writer) const;
};

/// Evaluates a domain binding, distinguishing "absent" from "present but not
/// current" so callers can never turn UNKNOWN into affirmative authority.
BindingState evaluate_domain(const AuthorityVector& vector, AuthorityDomain domain) noexcept;

/// Explicit fence. Any authority-bearing dependency change advances a fence,
/// which revokes everything issued under an older epoch/generation.
struct Fence {
  Epoch epoch{};
  BootId boot{};
  AuthorityDomain domain = AuthorityDomain::FABRIC_STATE;
  Generation minimum_generation{};
  Sequence sequence{};
  std::string reason;

  friend bool operator==(const Fence& a, const Fence& b);
  friend bool operator<(const Fence& a, const Fence& b);
};

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

enum class EvidenceKind : std::uint8_t {
  LINK_OPERATIONAL = 0,
  NODE_OPERATIONAL = 1,
  SERVICE_REACHABLE_ENDPOINTS = 2,
  RESOURCE_AVAILABLE_UNITS = 3,
  RESOURCE_RESTORED = 4,
  COUNT = 5,
};

const char* to_string(EvidenceKind kind) noexcept;
bool is_valid(EvidenceKind kind) noexcept;
/// Subject kind a given evidence kind must be attached to.
SubjectKind expected_subject(EvidenceKind kind) noexcept;

struct EvidenceFact {
  EvidenceId id{};
  EvidenceKind kind = EvidenceKind::LINK_OPERATIONAL;
  Subject subject{};
  std::uint64_t value = 0;
  Generation generation{};
  AuthorityDomain source_domain = AuthorityDomain::FABRIC_STATE;
  AuthorityId source{};
  TrustLabel label = TrustLabel::UNKNOWN;
  Sequence sequence{};

  friend bool operator==(const EvidenceFact& a, const EvidenceFact& b);
  friend bool operator<(const EvidenceFact& a, const EvidenceFact& b);
};

/// Outcome of reconciling evidence for one subject. Every non-current result is
/// surfaced explicitly instead of being mapped to success or plain absence.
enum class SubjectState : std::uint8_t {
  RESOLVED = 0,
  MISSING = 1,
  STALE = 2,
  AHEAD = 3,       // evidence generation ahead of granted authority: INVALID
  CONFLICT = 4,    // two admissible facts disagree
  INVALID = 5,     // structurally invalid fact (wrong subject kind, bad enum)
  UNSUPPORTED = 6, // declared trust label UNSUPPORTED
  COUNT = 7,
};

const char* to_string(SubjectState state) noexcept;

struct EvidenceBundle {
  Epoch coordinator_epoch{};
  BootId boot{};
  std::vector<EvidenceFact> facts;

  void canonicalise();
  Digest digest() const;
  void encode(CanonicalWriter& writer) const;
};

/// Canonical ordering for evidence lookup keys.
struct EvidenceKey {
  EvidenceKind kind = EvidenceKind::LINK_OPERATIONAL;
  Subject subject{};
  friend bool operator==(const EvidenceKey& a, const EvidenceKey& b) {
    return a.kind == b.kind && a.subject == b.subject;
  }
  friend bool operator<(const EvidenceKey& a, const EvidenceKey& b) {
    if (a.subject != b.subject) return a.subject < b.subject;
    return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
  }
};

// ---------------------------------------------------------------------------
// Explanations
// ---------------------------------------------------------------------------

/// Deterministic, closed-set explanation codes. Text never carries meaning.
enum class ReasonCode : std::uint8_t {
  NONE = 0,
  PLAN_ACCEPTED,
  PLAN_OPTIMAL_BY_OBJECTIVE,
  PROOF_EXHAUSTIVE_SEARCH,
  PROOF_DEPENDENCY_CYCLE,
  PROOF_GOAL_UPPER_BOUND,
  SEARCH_BUDGET_EXHAUSTED,
  EVIDENCE_SUBJECT_MISSING,
  EVIDENCE_SUBJECT_STALE,
  EVIDENCE_SUBJECT_AHEAD_OF_AUTHORITY,
  EVIDENCE_SUBJECT_CONFLICTING,
  EVIDENCE_SUBJECT_INVALID,
  EVIDENCE_SUBJECT_UNSUPPORTED,
  AUTHORITY_BINDING_MISSING,
  AUTHORITY_BINDING_STALE,
  AUTHORITY_BINDING_UNKNOWN,
  AUTHORITY_BINDING_CONFLICT,
  AUTHORITY_BINDING_INVALID,
  AUTHORITY_BINDING_UNSUPPORTED,
  AUTHORITY_LEVEL_INSUFFICIENT,
  REQUEST_INVALID_DEFINITION,
  REQUEST_UNSUPPORTED_PROBLEM,
  REQUEST_MALFORMED_ENCODING,
  REQUEST_POLICY_RESTRICTED_ACTION,
  REQUEST_FENCED_BY_EPOCH,
  VALIDATION_PRECONDITION_UNMET,
  VALIDATION_ORDERING_VIOLATION,
  VALIDATION_RESOURCE_VIOLATION,
  VALIDATION_SAFETY_VIOLATION,
  VALIDATION_AUTHORITY_MISMATCH,
  VALIDATION_EVIDENCE_BINDING_MISMATCH,
  VALIDATION_GOAL_UNMET,
  VALIDATION_OBJECTIVE_MISMATCH,
  VALIDATION_DIGEST_MISMATCH,
  VALIDATION_OCCURRENCE_EXCEEDED,
  VALIDATION_EXCLUSION_VIOLATION,
  VALIDATION_COMPENSATION_MISSING,
  VALIDATION_FENCED,
  PERSISTENCE_INTEGRITY_FAILURE,
  PERSISTENCE_VERSION_UNSUPPORTED,
  PERSISTENCE_SEQUENCE_REGRESSION,
  PERSISTENCE_TRAILING_GARBAGE,
  PERSISTENCE_TORN_TAIL_RECOVERED,
  PERSISTENCE_EPOCH_ADVANCED,
  PERSISTENCE_STALE_DYNAMIC_STATE_FENCED,
  PROTOCOL_FRAME_TOO_LARGE,
  PROTOCOL_BAD_MAGIC,
  PROTOCOL_BAD_VERSION,
  PROTOCOL_BAD_CHECKSUM,
  PROTOCOL_TRUNCATED,
  PROTOCOL_TRAILING_BYTES,
  PROTOCOL_SEQUENCE_REGRESSION,
  PROTOCOL_SESSION_MISMATCH,
  PROTOCOL_STICKY_FAILURE,
  PROTOCOL_DECODE_REJECTED,
  SESSION_LIMIT_REACHED,
  QUEUE_LIMIT_REACHED,
  SHUTDOWN_REQUESTED,
  COUNT,
};

const char* to_string(ReasonCode code) noexcept;

struct Explanation {
  ReasonCode code = ReasonCode::NONE;
  Subject subject{};
  std::uint64_t detail_a = 0;
  std::uint64_t detail_b = 0;
  std::string text;

  friend bool operator==(const Explanation& a, const Explanation& b);
  friend bool operator<(const Explanation& a, const Explanation& b);
};

/// Bounded explanation list. Growth is capped; overflow is recorded explicitly
/// rather than silently dropped.
class ExplanationLog {
 public:
  explicit ExplanationLog(std::size_t cap = 64) : cap_(cap == 0 ? 1 : cap) {}

  void add(Explanation explanation);
  void add(ReasonCode code, std::string text);
  void add(ReasonCode code, Subject subject, std::uint64_t a, std::uint64_t b, std::string text);

  const std::vector<Explanation>& entries() const noexcept { return entries_; }
  bool overflowed() const noexcept { return overflowed_; }
  std::size_t capacity() const noexcept { return cap_; }
  bool empty() const noexcept { return entries_.empty(); }

  std::string render() const;

 private:
  std::vector<Explanation> entries_;
  std::size_t cap_;
  bool overflowed_ = false;
};

}  // namespace nrp

#endif  // NRP_MODEL_HPP
