// Network Recovery Planner - authority, generations, evidence and outcomes.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "nrp/model.hpp"

#include <algorithm>
#include <sstream>

namespace nrp {

const char* to_string(TrustLabel label) noexcept {
  switch (label) {
    case TrustLabel::UNKNOWN: return "UNKNOWN";
    case TrustLabel::REAL: return "REAL";
    case TrustLabel::SYNTHETIC: return "SYNTHETIC";
    case TrustLabel::UNSUPPORTED: return "UNSUPPORTED";
  }
  return "UNRECOGNISED_TRUST_LABEL";
}

bool is_valid(TrustLabel label) noexcept {
  switch (label) {
    case TrustLabel::UNKNOWN:
    case TrustLabel::REAL:
    case TrustLabel::SYNTHETIC:
    case TrustLabel::UNSUPPORTED:
      return true;
  }
  return false;
}

const char* to_string(AuthorityDomain domain) noexcept {
  switch (domain) {
    case AuthorityDomain::FABRIC_STATE: return "FABRIC_STATE";
    case AuthorityDomain::RECOVERY_ADMISSION: return "RECOVERY_ADMISSION";
    case AuthorityDomain::RESOURCE_LEASE: return "RESOURCE_LEASE";
    case AuthorityDomain::POLICY: return "POLICY";
    case AuthorityDomain::EVIDENCE_INGEST: return "EVIDENCE_INGEST";
    case AuthorityDomain::COUNT: return "COUNT";
  }
  return "UNRECOGNISED_AUTHORITY_DOMAIN";
}

bool is_valid(AuthorityDomain domain) noexcept {
  switch (domain) {
    case AuthorityDomain::FABRIC_STATE:
    case AuthorityDomain::RECOVERY_ADMISSION:
    case AuthorityDomain::RESOURCE_LEASE:
    case AuthorityDomain::POLICY:
    case AuthorityDomain::EVIDENCE_INGEST:
      return true;
    case AuthorityDomain::COUNT:
      return false;
  }
  return false;
}

const char* to_string(AuthorityLevel level) noexcept {
  switch (level) {
    case AuthorityLevel::NONE: return "NONE";
    case AuthorityLevel::OBSERVATION: return "OBSERVATION";
    case AuthorityLevel::ELIGIBILITY: return "ELIGIBILITY";
    case AuthorityLevel::RECOMMENDATION: return "RECOMMENDATION";
    case AuthorityLevel::AUTHORIZATION: return "AUTHORIZATION";
    case AuthorityLevel::ACKNOWLEDGEMENT: return "ACKNOWLEDGEMENT";
    case AuthorityLevel::VERIFIED_EFFECT: return "VERIFIED_EFFECT";
    case AuthorityLevel::COUNT: return "COUNT";
  }
  return "UNRECOGNISED_AUTHORITY_LEVEL";
}

bool is_valid(AuthorityLevel level) noexcept {
  switch (level) {
    case AuthorityLevel::NONE:
    case AuthorityLevel::OBSERVATION:
    case AuthorityLevel::ELIGIBILITY:
    case AuthorityLevel::RECOMMENDATION:
    case AuthorityLevel::AUTHORIZATION:
    case AuthorityLevel::ACKNOWLEDGEMENT:
    case AuthorityLevel::VERIFIED_EFFECT:
      return true;
    case AuthorityLevel::COUNT:
      return false;
  }
  return false;
}

const char* to_string(BindingState state) noexcept {
  switch (state) {
    case BindingState::CURRENT: return "CURRENT";
    case BindingState::STALE: return "STALE";
    case BindingState::UNKNOWN: return "UNKNOWN";
    case BindingState::CONFLICT: return "CONFLICT";
    case BindingState::INVALID: return "INVALID";
    case BindingState::UNSUPPORTED: return "UNSUPPORTED";
    case BindingState::COUNT: return "COUNT";
  }
  return "UNRECOGNISED_BINDING_STATE";
}

BindingState AuthorityBinding::evaluate() const noexcept {
  if (authority.is_zero()) return BindingState::UNKNOWN;
  if (granted < required) return BindingState::STALE;
  if (granted > required) return BindingState::INVALID;
  if (level == AuthorityLevel::NONE) return BindingState::UNKNOWN;
  return BindingState::CURRENT;
}

bool operator==(const AuthorityBinding& a, const AuthorityBinding& b) {
  return a.domain == b.domain && a.authority == b.authority && a.required == b.required &&
         a.granted == b.granted && a.level == b.level;
}

bool operator<(const AuthorityBinding& a, const AuthorityBinding& b) {
  if (a.domain != b.domain) {
    return static_cast<std::uint8_t>(a.domain) < static_cast<std::uint8_t>(b.domain);
  }
  if (a.authority != b.authority) return a.authority < b.authority;
  if (a.required != b.required) return a.required < b.required;
  if (a.granted != b.granted) return a.granted < b.granted;
  return static_cast<std::uint8_t>(a.level) < static_cast<std::uint8_t>(b.level);
}

void AuthorityVector::canonicalise() {
  std::sort(bindings.begin(), bindings.end());
}

const AuthorityBinding* AuthorityVector::find(AuthorityDomain domain) const noexcept {
  for (const AuthorityBinding& binding : bindings) {
    if (binding.domain == domain) return &binding;
  }
  return nullptr;
}

bool AuthorityVector::all_current() const noexcept {
  // A duplicated domain is a contradiction, not two independent facts, so it
  // fails closed exactly like a stale binding.
  for (std::size_t index = 0; index < bindings.size(); ++index) {
    if (bindings[index].evaluate() != BindingState::CURRENT) return false;
    for (std::size_t other = index + 1; other < bindings.size(); ++other) {
      if (bindings[index].domain == bindings[other].domain) return false;
    }
  }
  return true;
}

void AuthorityVector::encode(CanonicalWriter& writer) const {
  writer.u64(coordinator_epoch.value());
  writer.u64(boot.value());
  writer.u32(static_cast<std::uint32_t>(bindings.size()));
  for (const AuthorityBinding& binding : bindings) {
    writer.u8(static_cast<std::uint8_t>(binding.domain));
    writer.u64(binding.authority.value());
    writer.u64(binding.required.value);
    writer.u64(binding.granted.value);
    writer.u8(static_cast<std::uint8_t>(binding.level));
  }
}

Digest AuthorityVector::digest() const {
  CanonicalWriter writer;
  encode(writer);
  return digest_of(writer.buffer());
}

BindingState evaluate_domain(const AuthorityVector& vector, AuthorityDomain domain) noexcept {
  const AuthorityBinding* found = nullptr;
  for (const AuthorityBinding& binding : vector.bindings) {
    if (binding.domain != domain) continue;
    if (found != nullptr) return BindingState::CONFLICT;  // two bindings for one domain
    found = &binding;
  }
  if (found == nullptr) return BindingState::UNKNOWN;  // absent is not current
  return found->evaluate();
}

bool operator==(const Fence& a, const Fence& b) {
  return a.epoch == b.epoch && a.boot == b.boot && a.domain == b.domain &&
         a.minimum_generation == b.minimum_generation && a.sequence == b.sequence &&
         a.reason == b.reason;
}

bool operator<(const Fence& a, const Fence& b) {
  if (a.epoch != b.epoch) return a.epoch < b.epoch;
  if (a.boot != b.boot) return a.boot < b.boot;
  if (a.domain != b.domain) {
    return static_cast<std::uint8_t>(a.domain) < static_cast<std::uint8_t>(b.domain);
  }
  if (a.minimum_generation != b.minimum_generation) return a.minimum_generation < b.minimum_generation;
  return a.sequence < b.sequence;
}

const char* to_string(EvidenceKind kind) noexcept {
  switch (kind) {
    case EvidenceKind::LINK_OPERATIONAL: return "LINK_OPERATIONAL";
    case EvidenceKind::NODE_OPERATIONAL: return "NODE_OPERATIONAL";
    case EvidenceKind::SERVICE_REACHABLE_ENDPOINTS: return "SERVICE_REACHABLE_ENDPOINTS";
    case EvidenceKind::RESOURCE_AVAILABLE_UNITS: return "RESOURCE_AVAILABLE_UNITS";
    case EvidenceKind::RESOURCE_RESTORED: return "RESOURCE_RESTORED";
    case EvidenceKind::COUNT: return "COUNT";
  }
  return "UNRECOGNISED_EVIDENCE_KIND";
}

bool is_valid(EvidenceKind kind) noexcept {
  switch (kind) {
    case EvidenceKind::LINK_OPERATIONAL:
    case EvidenceKind::NODE_OPERATIONAL:
    case EvidenceKind::SERVICE_REACHABLE_ENDPOINTS:
    case EvidenceKind::RESOURCE_AVAILABLE_UNITS:
    case EvidenceKind::RESOURCE_RESTORED:
      return true;
    case EvidenceKind::COUNT:
      return false;
  }
  return false;
}

SubjectKind expected_subject(EvidenceKind kind) noexcept {
  switch (kind) {
    case EvidenceKind::LINK_OPERATIONAL: return SubjectKind::LINK;
    case EvidenceKind::NODE_OPERATIONAL: return SubjectKind::NODE;
    case EvidenceKind::SERVICE_REACHABLE_ENDPOINTS: return SubjectKind::SERVICE;
    case EvidenceKind::RESOURCE_AVAILABLE_UNITS: return SubjectKind::RESOURCE;
    case EvidenceKind::RESOURCE_RESTORED: return SubjectKind::RESOURCE;
    case EvidenceKind::COUNT: return SubjectKind::NONE;
  }
  return SubjectKind::NONE;
}

bool operator==(const EvidenceFact& a, const EvidenceFact& b) {
  return a.id == b.id && a.kind == b.kind && a.subject == b.subject && a.value == b.value &&
         a.generation == b.generation && a.source_domain == b.source_domain && a.source == b.source &&
         a.label == b.label && a.sequence == b.sequence;
}

bool operator<(const EvidenceFact& a, const EvidenceFact& b) {
  if (a.subject != b.subject) return a.subject < b.subject;
  if (a.kind != b.kind) {
    return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
  }
  if (a.source_domain != b.source_domain) {
    return static_cast<std::uint8_t>(a.source_domain) < static_cast<std::uint8_t>(b.source_domain);
  }
  if (a.source != b.source) return a.source < b.source;
  if (a.sequence != b.sequence) return a.sequence < b.sequence;
  if (a.generation != b.generation) return a.generation < b.generation;
  if (a.value != b.value) return a.value < b.value;
  return a.id < b.id;
}

const char* to_string(SubjectState state) noexcept {
  switch (state) {
    case SubjectState::RESOLVED: return "RESOLVED";
    case SubjectState::MISSING: return "MISSING";
    case SubjectState::STALE: return "STALE";
    case SubjectState::AHEAD: return "AHEAD";
    case SubjectState::CONFLICT: return "CONFLICT";
    case SubjectState::INVALID: return "INVALID";
    case SubjectState::UNSUPPORTED: return "UNSUPPORTED";
    case SubjectState::COUNT: return "COUNT";
  }
  return "UNRECOGNISED_SUBJECT_STATE";
}

void EvidenceBundle::canonicalise() {
  std::sort(facts.begin(), facts.end());
}

void EvidenceBundle::encode(CanonicalWriter& writer) const {
  writer.u64(coordinator_epoch.value());
  writer.u64(boot.value());
  writer.u32(static_cast<std::uint32_t>(facts.size()));
  for (const EvidenceFact& fact : facts) {
    writer.u64(fact.id.value());
    writer.u8(static_cast<std::uint8_t>(fact.kind));
    writer.u8(static_cast<std::uint8_t>(fact.subject.kind));
    writer.u64(fact.subject.id);
    writer.u64(fact.value);
    writer.u64(fact.generation.value);
    writer.u8(static_cast<std::uint8_t>(fact.source_domain));
    writer.u64(fact.source.value());
    writer.u8(static_cast<std::uint8_t>(fact.label));
    writer.u64(fact.sequence.value);
  }
}

Digest EvidenceBundle::digest() const {
  CanonicalWriter writer;
  encode(writer);
  return digest_of(writer.buffer());
}

const char* to_string(ReasonCode code) noexcept {
  switch (code) {
    case ReasonCode::NONE: return "NONE";
    case ReasonCode::PLAN_ACCEPTED: return "PLAN_ACCEPTED";
    case ReasonCode::PLAN_OPTIMAL_BY_OBJECTIVE: return "PLAN_OPTIMAL_BY_OBJECTIVE";
    case ReasonCode::PROOF_EXHAUSTIVE_SEARCH: return "PROOF_EXHAUSTIVE_SEARCH";
    case ReasonCode::PROOF_DEPENDENCY_CYCLE: return "PROOF_DEPENDENCY_CYCLE";
    case ReasonCode::PROOF_GOAL_UPPER_BOUND: return "PROOF_GOAL_UPPER_BOUND";
    case ReasonCode::SEARCH_BUDGET_EXHAUSTED: return "SEARCH_BUDGET_EXHAUSTED";
    case ReasonCode::EVIDENCE_SUBJECT_MISSING: return "EVIDENCE_SUBJECT_MISSING";
    case ReasonCode::EVIDENCE_SUBJECT_STALE: return "EVIDENCE_SUBJECT_STALE";
    case ReasonCode::EVIDENCE_SUBJECT_AHEAD_OF_AUTHORITY: return "EVIDENCE_SUBJECT_AHEAD_OF_AUTHORITY";
    case ReasonCode::EVIDENCE_SUBJECT_CONFLICTING: return "EVIDENCE_SUBJECT_CONFLICTING";
    case ReasonCode::EVIDENCE_SUBJECT_INVALID: return "EVIDENCE_SUBJECT_INVALID";
    case ReasonCode::EVIDENCE_SUBJECT_UNSUPPORTED: return "EVIDENCE_SUBJECT_UNSUPPORTED";
    case ReasonCode::AUTHORITY_BINDING_MISSING: return "AUTHORITY_BINDING_MISSING";
    case ReasonCode::AUTHORITY_BINDING_STALE: return "AUTHORITY_BINDING_STALE";
    case ReasonCode::AUTHORITY_BINDING_UNKNOWN: return "AUTHORITY_BINDING_UNKNOWN";
    case ReasonCode::AUTHORITY_BINDING_CONFLICT: return "AUTHORITY_BINDING_CONFLICT";
    case ReasonCode::AUTHORITY_BINDING_INVALID: return "AUTHORITY_BINDING_INVALID";
    case ReasonCode::AUTHORITY_BINDING_UNSUPPORTED: return "AUTHORITY_BINDING_UNSUPPORTED";
    case ReasonCode::AUTHORITY_LEVEL_INSUFFICIENT: return "AUTHORITY_LEVEL_INSUFFICIENT";
    case ReasonCode::REQUEST_INVALID_DEFINITION: return "REQUEST_INVALID_DEFINITION";
    case ReasonCode::REQUEST_UNSUPPORTED_PROBLEM: return "REQUEST_UNSUPPORTED_PROBLEM";
    case ReasonCode::REQUEST_MALFORMED_ENCODING: return "REQUEST_MALFORMED_ENCODING";
    case ReasonCode::REQUEST_POLICY_RESTRICTED_ACTION: return "REQUEST_POLICY_RESTRICTED_ACTION";
    case ReasonCode::REQUEST_FENCED_BY_EPOCH: return "REQUEST_FENCED_BY_EPOCH";
    case ReasonCode::VALIDATION_PRECONDITION_UNMET: return "VALIDATION_PRECONDITION_UNMET";
    case ReasonCode::VALIDATION_ORDERING_VIOLATION: return "VALIDATION_ORDERING_VIOLATION";
    case ReasonCode::VALIDATION_RESOURCE_VIOLATION: return "VALIDATION_RESOURCE_VIOLATION";
    case ReasonCode::VALIDATION_SAFETY_VIOLATION: return "VALIDATION_SAFETY_VIOLATION";
    case ReasonCode::VALIDATION_AUTHORITY_MISMATCH: return "VALIDATION_AUTHORITY_MISMATCH";
    case ReasonCode::VALIDATION_EVIDENCE_BINDING_MISMATCH: return "VALIDATION_EVIDENCE_BINDING_MISMATCH";
    case ReasonCode::VALIDATION_GOAL_UNMET: return "VALIDATION_GOAL_UNMET";
    case ReasonCode::VALIDATION_OBJECTIVE_MISMATCH: return "VALIDATION_OBJECTIVE_MISMATCH";
    case ReasonCode::VALIDATION_DIGEST_MISMATCH: return "VALIDATION_DIGEST_MISMATCH";
    case ReasonCode::VALIDATION_OCCURRENCE_EXCEEDED: return "VALIDATION_OCCURRENCE_EXCEEDED";
    case ReasonCode::VALIDATION_EXCLUSION_VIOLATION: return "VALIDATION_EXCLUSION_VIOLATION";
    case ReasonCode::VALIDATION_COMPENSATION_MISSING: return "VALIDATION_COMPENSATION_MISSING";
    case ReasonCode::VALIDATION_FENCED: return "VALIDATION_FENCED";
    case ReasonCode::PERSISTENCE_INTEGRITY_FAILURE: return "PERSISTENCE_INTEGRITY_FAILURE";
    case ReasonCode::PERSISTENCE_VERSION_UNSUPPORTED: return "PERSISTENCE_VERSION_UNSUPPORTED";
    case ReasonCode::PERSISTENCE_SEQUENCE_REGRESSION: return "PERSISTENCE_SEQUENCE_REGRESSION";
    case ReasonCode::PERSISTENCE_TRAILING_GARBAGE: return "PERSISTENCE_TRAILING_GARBAGE";
    case ReasonCode::PERSISTENCE_TORN_TAIL_RECOVERED: return "PERSISTENCE_TORN_TAIL_RECOVERED";
    case ReasonCode::PERSISTENCE_EPOCH_ADVANCED: return "PERSISTENCE_EPOCH_ADVANCED";
    case ReasonCode::PERSISTENCE_STALE_DYNAMIC_STATE_FENCED:
      return "PERSISTENCE_STALE_DYNAMIC_STATE_FENCED";
    case ReasonCode::PROTOCOL_FRAME_TOO_LARGE: return "PROTOCOL_FRAME_TOO_LARGE";
    case ReasonCode::PROTOCOL_BAD_MAGIC: return "PROTOCOL_BAD_MAGIC";
    case ReasonCode::PROTOCOL_BAD_VERSION: return "PROTOCOL_BAD_VERSION";
    case ReasonCode::PROTOCOL_BAD_CHECKSUM: return "PROTOCOL_BAD_CHECKSUM";
    case ReasonCode::PROTOCOL_TRUNCATED: return "PROTOCOL_TRUNCATED";
    case ReasonCode::PROTOCOL_TRAILING_BYTES: return "PROTOCOL_TRAILING_BYTES";
    case ReasonCode::PROTOCOL_SEQUENCE_REGRESSION: return "PROTOCOL_SEQUENCE_REGRESSION";
    case ReasonCode::PROTOCOL_SESSION_MISMATCH: return "PROTOCOL_SESSION_MISMATCH";
    case ReasonCode::PROTOCOL_STICKY_FAILURE: return "PROTOCOL_STICKY_FAILURE";
    case ReasonCode::PROTOCOL_DECODE_REJECTED: return "PROTOCOL_DECODE_REJECTED";
    case ReasonCode::SESSION_LIMIT_REACHED: return "SESSION_LIMIT_REACHED";
    case ReasonCode::QUEUE_LIMIT_REACHED: return "QUEUE_LIMIT_REACHED";
    case ReasonCode::SHUTDOWN_REQUESTED: return "SHUTDOWN_REQUESTED";
    case ReasonCode::COUNT: return "COUNT";
  }
  return "UNRECOGNISED_REASON_CODE";
}

bool operator==(const Explanation& a, const Explanation& b) {
  return a.code == b.code && a.subject == b.subject && a.detail_a == b.detail_a &&
         a.detail_b == b.detail_b && a.text == b.text;
}

bool operator<(const Explanation& a, const Explanation& b) {
  if (a.code != b.code) {
    return static_cast<std::uint8_t>(a.code) < static_cast<std::uint8_t>(b.code);
  }
  if (a.subject != b.subject) return a.subject < b.subject;
  if (a.detail_a != b.detail_a) return a.detail_a < b.detail_a;
  if (a.detail_b != b.detail_b) return a.detail_b < b.detail_b;
  return a.text < b.text;
}

void ExplanationLog::add(Explanation explanation) {
  if (entries_.size() >= cap_) {
    // Growth is bounded. The truncation itself is recorded once, explicitly,
    // instead of silently discarding information.
    if (!overflowed_) {
      overflowed_ = true;
      Explanation marker;
      marker.code = ReasonCode::REQUEST_UNSUPPORTED_PROBLEM;
      marker.text = "explanation log capacity reached; further entries truncated";
      if (!entries_.empty()) entries_.back() = std::move(marker);
      else entries_.push_back(std::move(marker));
    }
    return;
  }
  entries_.push_back(std::move(explanation));
}

void ExplanationLog::add(ReasonCode code, std::string text) {
  Explanation explanation;
  explanation.code = code;
  explanation.text = std::move(text);
  add(std::move(explanation));
}

void ExplanationLog::add(ReasonCode code,
                         Subject subject,
                         std::uint64_t a,
                         std::uint64_t b,
                         std::string text) {
  Explanation explanation;
  explanation.code = code;
  explanation.subject = subject;
  explanation.detail_a = a;
  explanation.detail_b = b;
  explanation.text = std::move(text);
  add(std::move(explanation));
}

std::string ExplanationLog::render() const {
  std::ostringstream out;
  for (const Explanation& entry : entries_) {
    out << to_string(entry.code);
    if (entry.subject.kind != SubjectKind::NONE) out << " " << describe(entry.subject);
    if (entry.detail_a != 0 || entry.detail_b != 0) {
      out << " [" << entry.detail_a << "," << entry.detail_b << "]";
    }
    if (!entry.text.empty()) out << ": " << entry.text;
    out << '\n';
  }
  if (overflowed_) out << "(explanation log truncated at capacity)\n";
  return out.str();
}

}  // namespace nrp
