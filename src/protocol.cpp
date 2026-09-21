// Network Recovery Planner - bounded framed transport protocol.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Frame layout (56 byte header, little endian, format version 1):
//   0  magic u32          4  version u16      6  type u16
//   8  flags u16         10  reserved u16    12  session_id u64
//  20  epoch u64         28  boot u64        36  sequence u64
//  44  payload_length u32
//  48  payload_crc32 u32 52  header_crc32 u32   (over bytes 0..51)
//
// Decoding is total and one-way: the declared payload length is checked against
// the configured bound before any allocation, every enumeration and range is
// validated, and trailing bytes are rejected. A decode failure is sticky - the
// caller must close the connection rather than try to resynchronise.
#include "nrp/protocol.hpp"

#include <algorithm>
#include <cstring>

#include "detail/crc32.hpp"
#include "nrp/codec.hpp"

namespace nrp {
namespace {

void write_u16(std::uint8_t* out, std::uint16_t value) {
  out[0] = static_cast<std::uint8_t>(value & 0xFFu);
  out[1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
}

void write_u32(std::uint8_t* out, std::uint32_t value) {
  for (int index = 0; index < 4; ++index) {
    out[index] = static_cast<std::uint8_t>((value >> (8 * index)) & 0xFFu);
  }
}

void write_u64(std::uint8_t* out, std::uint64_t value) {
  for (int index = 0; index < 8; ++index) {
    out[index] = static_cast<std::uint8_t>((value >> (8 * index)) & 0xFFu);
  }
}

std::uint16_t read_u16(const std::uint8_t* data) {
  return static_cast<std::uint16_t>(data[0] | (data[1] << 8));
}

std::uint32_t read_u32(const std::uint8_t* data) {
  return static_cast<std::uint32_t>(data[0]) | (static_cast<std::uint32_t>(data[1]) << 8) |
         (static_cast<std::uint32_t>(data[2]) << 16) | (static_cast<std::uint32_t>(data[3]) << 24);
}

std::uint64_t read_u64(const std::uint8_t* data) {
  std::uint64_t value = 0;
  for (int index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(data[index]) << (8 * index);
  }
  return value;
}

void encode_digest(CanonicalWriter& writer, const Digest& digest) {
  writer.u64(digest.hi);
  writer.u64(digest.lo);
}

Digest decode_digest(CanonicalReader& reader) {
  Digest digest;
  digest.hi = reader.u64();
  digest.lo = reader.u64();
  return digest;
}

void encode_certificate(CanonicalWriter& writer, const InfeasibilityCertificate& certificate) {
  writer.u8(static_cast<std::uint8_t>(certificate.kind));
  encode_digest(writer, certificate.request_digest);
  encode_digest(writer, certificate.policy_digest);
  writer.u64(certificate.nodes_expanded);
  writer.u64(certificate.nodes_generated);
  writer.u64(certificate.reachable_states);
  writer.u32(static_cast<std::uint32_t>(certificate.cycle.size()));
  for (const ActionId& action : certificate.cycle) writer.u64(action.value());
  writer.u8(static_cast<std::uint8_t>(certificate.unreachable_subject.kind));
  writer.u64(certificate.unreachable_subject.id);
  writer.u64(certificate.unreachable_value);
  writer.u64(certificate.required_value);
  writer.u32(static_cast<std::uint32_t>(certificate.assumptions.size()));
  for (const std::string& assumption : certificate.assumptions) writer.str(assumption);
  writer.u32(static_cast<std::uint32_t>(certificate.explanations.size()));
  for (const Explanation& explanation : certificate.explanations) {
    encode_explanation(writer, explanation);
  }
}

Status decode_certificate(CanonicalReader& reader,
                          const ModelLimits& limits,
                          InfeasibilityCertificate* out) {
  InfeasibilityCertificate certificate;
  certificate.kind = reader.enum_value<ProofKind>(3, "proof kind");
  certificate.request_digest = decode_digest(reader);
  certificate.policy_digest = decode_digest(reader);
  certificate.nodes_expanded = reader.u64();
  certificate.nodes_generated = reader.u64();
  certificate.reachable_states = reader.u64();
  const std::uint32_t cycle_count = reader.bounded_count(limits.max_actions, "proof cycle");
  if (!reader.ok()) return reader.status();
  certificate.cycle.reserve(cycle_count);
  for (std::uint32_t index = 0; index < cycle_count; ++index) {
    certificate.cycle.push_back(ActionId::from_value(reader.u64()));
    if (!reader.ok()) return reader.status();
  }
  certificate.unreachable_subject.kind = reader.enum_value<SubjectKind>(7, "proof subject kind");
  certificate.unreachable_subject.id = reader.u64();
  certificate.unreachable_value = reader.u64();
  certificate.required_value = reader.u64();
  const std::uint32_t assumption_count = reader.bounded_count(32, "proof assumptions");
  if (!reader.ok()) return reader.status();
  certificate.assumptions.reserve(assumption_count);
  for (std::uint32_t index = 0; index < assumption_count; ++index) {
    certificate.assumptions.push_back(reader.str(limits.max_string_length * 4));
    if (!reader.ok()) return reader.status();
  }
  const std::uint32_t explanation_count = reader.bounded_count(64, "proof explanations");
  if (!reader.ok()) return reader.status();
  certificate.explanations.reserve(explanation_count);
  for (std::uint32_t index = 0; index < explanation_count; ++index) {
    Explanation explanation;
    const Status status = decode_explanation(reader, limits, &explanation);
    if (!status.ok()) return status;
    certificate.explanations.push_back(std::move(explanation));
  }
  *out = std::move(certificate);
  return Status::success();
}

}  // namespace

const char* to_string(FrameType type) noexcept {
  switch (type) {
    case FrameType::HELLO: return "HELLO";
    case FrameType::HELLO_ACK: return "HELLO_ACK";
    case FrameType::PLAN_REQUEST: return "PLAN_REQUEST";
    case FrameType::PLAN_RESPONSE: return "PLAN_RESPONSE";
    case FrameType::VALIDATE_REQUEST: return "VALIDATE_REQUEST";
    case FrameType::VALIDATE_RESPONSE: return "VALIDATE_RESPONSE";
    case FrameType::STATUS_REQUEST: return "STATUS_REQUEST";
    case FrameType::STATUS_RESPONSE: return "STATUS_RESPONSE";
    case FrameType::BYE: return "BYE";
    case FrameType::ERROR_FRAME: return "ERROR";
    case FrameType::COUNT: return "COUNT";
  }
  return "UNRECOGNISED_FRAME_TYPE";
}

bool is_valid(FrameType type) noexcept {
  return type != FrameType::COUNT &&
         static_cast<std::uint16_t>(type) < static_cast<std::uint16_t>(FrameType::COUNT);
}

const char* to_string(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::NONE: return "NONE";
    case ErrorCode::BAD_MAGIC: return "BAD_MAGIC";
    case ErrorCode::BAD_VERSION: return "BAD_VERSION";
    case ErrorCode::BAD_HEADER_CHECKSUM: return "BAD_HEADER_CHECKSUM";
    case ErrorCode::BAD_PAYLOAD_CHECKSUM: return "BAD_PAYLOAD_CHECKSUM";
    case ErrorCode::FRAME_TOO_LARGE: return "FRAME_TOO_LARGE";
    case ErrorCode::INVALID_ENUM: return "INVALID_ENUM";
    case ErrorCode::INVALID_LENGTH: return "INVALID_LENGTH";
    case ErrorCode::TRAILING_BYTES: return "TRAILING_BYTES";
    case ErrorCode::SEQUENCE_REGRESSION: return "SEQUENCE_REGRESSION";
    case ErrorCode::SESSION_MISMATCH: return "SESSION_MISMATCH";
    case ErrorCode::SESSION_LIMIT: return "SESSION_LIMIT";
    case ErrorCode::QUEUE_LIMIT: return "QUEUE_LIMIT";
    case ErrorCode::UNSUPPORTED_REQUEST: return "UNSUPPORTED_REQUEST";
    case ErrorCode::DECODE_REJECTED: return "DECODE_REJECTED";
    case ErrorCode::STICKY_FAILURE: return "STICKY_FAILURE";
    case ErrorCode::SHUTTING_DOWN: return "SHUTTING_DOWN";
    case ErrorCode::COUNT: return "COUNT";
  }
  return "UNRECOGNISED_ERROR_CODE";
}

bool is_valid(ErrorCode code) noexcept {
  return static_cast<std::uint16_t>(code) < static_cast<std::uint16_t>(ErrorCode::COUNT);
}

void encode_frame_header(const FrameHeader& header, std::uint8_t out[kFrameHeaderSize]) {
  std::memset(out, 0, kFrameHeaderSize);
  write_u32(out, header.magic);
  write_u16(out + 4, header.version);
  write_u16(out + 6, header.type);
  write_u16(out + 8, header.flags);
  write_u16(out + 10, header.reserved);
  write_u64(out + 12, header.session_id);
  write_u64(out + 20, header.epoch);
  write_u64(out + 28, header.boot);
  write_u64(out + 36, header.sequence);
  write_u32(out + 44, header.payload_length);
  write_u32(out + 48, header.payload_crc32);
  write_u32(out + 52, detail::crc32(out, 52));
}

Result<FrameHeader> decode_frame_header(const std::uint8_t* bytes, std::size_t size) {
  if (size < kFrameHeaderSize) {
    return Status::error(StatusCode::PROTOCOL_ERROR, "frame header is a truncated prefix");
  }
  if (read_u32(bytes) != kFrameMagic) {
    return Status::error(StatusCode::PROTOCOL_ERROR, "frame magic mismatch");
  }
  FrameHeader header;
  header.magic = kFrameMagic;
  header.version = read_u16(bytes + 4);
  if (header.version != kProtocolVersion) {
    return Status::error(StatusCode::UNSUPPORTED, "protocol version is not supported: " +
                                                      std::to_string(header.version));
  }
  header.type = read_u16(bytes + 6);
  const FrameType type = static_cast<FrameType>(header.type);
  if (header.type == 0 || !is_valid(type)) {
    return Status::error(StatusCode::PROTOCOL_ERROR, "frame type is outside the defined domain");
  }
  header.flags = read_u16(bytes + 8);
  header.reserved = read_u16(bytes + 10);
  if (header.flags != 0 || header.reserved != 0) {
    return Status::error(StatusCode::PROTOCOL_ERROR, "reserved frame header bits are set");
  }
  header.session_id = read_u64(bytes + 12);
  header.epoch = read_u64(bytes + 20);
  header.boot = read_u64(bytes + 28);
  header.sequence = read_u64(bytes + 36);
  header.payload_length = read_u32(bytes + 44);
  header.payload_crc32 = read_u32(bytes + 48);
  header.header_crc32 = read_u32(bytes + 52);
  if (header.header_crc32 != detail::crc32(bytes, 52)) {
    return Status::error(StatusCode::PROTOCOL_ERROR, "frame header checksum mismatch");
  }
  return header;
}

std::vector<std::uint8_t> encode_frame(FrameType type,
                                       std::uint64_t session_id,
                                       Epoch epoch,
                                       BootId boot,
                                       Sequence sequence,
                                       const std::vector<std::uint8_t>& payload) {
  FrameHeader header;
  header.type = static_cast<std::uint16_t>(type);
  header.session_id = session_id;
  header.epoch = epoch.value();
  header.boot = boot.value();
  header.sequence = sequence.value;
  header.payload_length = static_cast<std::uint32_t>(payload.size());
  header.payload_crc32 = detail::crc32(payload.data(), payload.size());
  std::vector<std::uint8_t> bytes(kFrameHeaderSize + payload.size(), 0);
  encode_frame_header(header, bytes.data());
  if (!payload.empty()) std::memcpy(bytes.data() + kFrameHeaderSize, payload.data(), payload.size());
  return bytes;
}

Status decode_frame(const std::uint8_t* data,
                    std::size_t size,
                    const ProtocolLimits& limits,
                    Frame* out,
                    std::size_t* consumed) {
  if (size < kFrameHeaderSize) {
    // Not an error yet: the caller reads more bytes. NOT_FOUND is the
    // "incomplete input" signal used consistently across this runtime.
    return Status::error(StatusCode::NOT_FOUND, "frame header is incomplete");
  }
  const Result<FrameHeader> header = decode_frame_header(data, size);
  if (!header.ok()) return header.status();
  if (header.value().payload_length > limits.max_payload_bytes) {
    // Refused before any allocation is attempted.
    return Status::error(StatusCode::OUT_OF_RANGE, "declared payload exceeds the frame bound");
  }
  const std::size_t total = kFrameHeaderSize + header.value().payload_length;
  if (size < total) {
    return Status::error(StatusCode::NOT_FOUND, "frame payload is incomplete");
  }
  const std::uint8_t* payload = data + kFrameHeaderSize;
  if (detail::crc32(payload, header.value().payload_length) != header.value().payload_crc32) {
    return Status::error(StatusCode::PROTOCOL_ERROR, "frame payload checksum mismatch");
  }
  out->header = header.value();
  out->payload.assign(payload, payload + header.value().payload_length);
  if (consumed != nullptr) *consumed = total;
  return Status::success();
}

// ---------------------------------------------------------------------------
// Payload codecs
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> encode_hello(std::uint64_t client_nonce,
                                       std::uint32_t requested_features) {
  CanonicalWriter writer;
  writer.u64(client_nonce);
  writer.u32(requested_features);
  return writer.take();
}

Result<std::uint64_t> decode_hello(const std::vector<std::uint8_t>& payload) {
  CanonicalReader reader(payload);
  const std::uint64_t nonce = reader.u64();
  (void)reader.u32();
  const Status status = reader.require_end();
  if (!status.ok()) return status;
  if (nonce == 0) {
    return Status::error(StatusCode::PROTOCOL_ERROR, "hello nonce must be non-zero");
  }
  return nonce;
}

std::vector<std::uint8_t> encode_hello_ack(SessionId session,
                                           Epoch epoch,
                                           BootId boot,
                                           std::uint64_t server_nonce,
                                           Sequence next_sequence) {
  CanonicalWriter writer;
  writer.u64(session.value());
  writer.u64(epoch.value());
  writer.u64(boot.value());
  writer.u64(server_nonce);
  writer.u64(next_sequence.value);
  return writer.take();
}

Result<HelloAck> decode_hello_ack(const std::vector<std::uint8_t>& payload) {
  CanonicalReader reader(payload);
  HelloAck ack;
  ack.session = SessionId::from_value(reader.u64());
  ack.epoch = Epoch::from_value(reader.u64());
  ack.boot = BootId::from_value(reader.u64());
  ack.server_nonce = reader.u64();
  ack.next_sequence = Sequence{reader.u64()};
  if (!reader.ok()) return reader.status();
  const Status status = reader.require_end();
  if (!status.ok()) return status;
  if (ack.session.is_zero()) {
    return Status::error(StatusCode::PROTOCOL_ERROR, "session identity must be non-zero");
  }
  if (ack.next_sequence.value == 0) {
    return Status::error(StatusCode::PROTOCOL_ERROR, "next sequence must be at least one");
  }
  return ack;
}

std::vector<std::uint8_t> encode_error_payload(ErrorCode code,
                                               ReasonCode reason,
                                               std::string_view text) {
  CanonicalWriter writer;
  writer.u16(static_cast<std::uint16_t>(code));
  writer.u8(static_cast<std::uint8_t>(reason));
  writer.str(text);
  return writer.take();
}

Result<ErrorPayload> decode_error_payload(const std::vector<std::uint8_t>& payload) {
  CanonicalReader reader(payload);
  ErrorPayload error;
  error.code = static_cast<ErrorCode>(reader.u16());
  if (reader.ok() && !is_valid(error.code)) {
    reader.fail(StatusCode::PROTOCOL_ERROR, "error code is outside the defined domain");
  }
  error.reason = reader.enum_value<ReasonCode>(static_cast<std::uint8_t>(ReasonCode::COUNT),
                                               "error reason");
  error.text = reader.str(512);
  if (!reader.ok()) return reader.status();
  const Status status = reader.require_end();
  if (!status.ok()) return status;
  return error;
}

std::vector<std::uint8_t> encode_plan_request_payload(const PlanRequest& request) {
  CanonicalWriter writer;
  request.encode(writer);
  return writer.take();
}

Result<PlanRequest> decode_plan_request_payload(const std::vector<std::uint8_t>& payload,
                                                const ProtocolLimits& limits) {
  CanonicalReader reader(payload);
  PlanRequest request;
  Status status = decode_plan_request_body(reader, limits.model, &request);
  if (!status.ok()) return status;
  status = reader.require_end();
  if (!status.ok()) return status;
  ExplanationLog log(16);
  status = validate_definition(request.definition, limits.model, &log);
  if (!status.ok()) return status;
  if (request.definition.actions.size() > limits.max_records_per_message) {
    return Status::error(StatusCode::OUT_OF_RANGE, "request declares too many actions");
  }
  return request;
}

std::vector<std::uint8_t> encode_plan_response_payload(const PlanningResult& result) {
  CanonicalWriter writer;
  writer.u8(static_cast<std::uint8_t>(result.decision));
  writer.u64(result.request.value());
  writer.u64(result.coordinator_epoch.value());
  writer.u64(result.boot.value());
  writer.u64(result.attempt.value());
  writer.boolean(result.plan.has_value());
  if (result.plan.has_value()) {
    encode_plan(*result.plan, writer);
    encode_digest(writer, result.plan->plan_digest);
  }
  writer.boolean(result.certificate.has_value());
  if (result.certificate.has_value()) {
    encode_certificate(writer, *result.certificate);
  }
  writer.u64(result.stats.nodes_expanded);
  writer.u64(result.stats.nodes_generated);
  writer.u64(result.stats.nodes_pruned_by_dominance);
  writer.u64(result.stats.nodes_pruned_by_safety);
  writer.u64(result.stats.nodes_pruned_by_authority);
  writer.u64(result.stats.nodes_pruned_by_policy);
  writer.u64(result.stats.frontier_high_water);
  writer.u64(result.stats.states_revisited);
  writer.u64(result.stats.budget_nodes);
  writer.boolean(result.stats.budget_exhausted);
  writer.boolean(result.stats.frontier_emptied);
  writer.u32(static_cast<std::uint32_t>(result.unresolved_subjects.size()));
  for (const Subject& subject : result.unresolved_subjects) {
    writer.u8(static_cast<std::uint8_t>(subject.kind));
    writer.u64(subject.id);
  }
  writer.u32(static_cast<std::uint32_t>(result.explanations.size()));
  for (const Explanation& explanation : result.explanations) {
    encode_explanation(writer, explanation);
  }
  encode_digest(writer, result.request_digest);
  return writer.take();
}

Result<PlanningResult> decode_plan_response_payload(const std::vector<std::uint8_t>& payload,
                                                    const ProtocolLimits& limits) {
  CanonicalReader reader(payload);
  PlanningResult result;
  result.decision = reader.enum_value<PlanDecision>(static_cast<std::uint8_t>(PlanDecision::COUNT),
                                                    "plan decision");
  result.request = RequestId::from_value(reader.u64());
  result.coordinator_epoch = Epoch::from_value(reader.u64());
  result.boot = BootId::from_value(reader.u64());
  result.attempt = AttemptId::from_value(reader.u64());
  if (!reader.ok()) return reader.status();
  if (!is_valid(result.decision)) {
    return Status::error(StatusCode::PROTOCOL_ERROR, "plan decision is outside the domain");
  }
  if (reader.boolean()) {
    RecoveryPlan plan;
    Status status = decode_plan(reader, limits.model, &plan);
    if (!status.ok()) return status;
    plan.plan_digest = decode_digest(reader);
    result.plan = std::move(plan);
  }
  if (!reader.ok()) return reader.status();
  if (reader.boolean()) {
    InfeasibilityCertificate certificate;
    const Status status = decode_certificate(reader, limits.model, &certificate);
    if (!status.ok()) return status;
    result.certificate = std::move(certificate);
  }
  if (!reader.ok()) return reader.status();
  result.stats.nodes_expanded = reader.u64();
  result.stats.nodes_generated = reader.u64();
  result.stats.nodes_pruned_by_dominance = reader.u64();
  result.stats.nodes_pruned_by_safety = reader.u64();
  result.stats.nodes_pruned_by_authority = reader.u64();
  result.stats.nodes_pruned_by_policy = reader.u64();
  result.stats.frontier_high_water = reader.u64();
  result.stats.states_revisited = reader.u64();
  result.stats.budget_nodes = reader.u64();
  result.stats.budget_exhausted = reader.boolean();
  result.stats.frontier_emptied = reader.boolean();
  const std::uint32_t unresolved_count =
      reader.bounded_count(limits.model.max_nodes + limits.model.max_links +
                               limits.model.max_services + limits.model.max_resources,
                           "unresolved subjects");
  if (!reader.ok()) return reader.status();
  result.unresolved_subjects.reserve(unresolved_count);
  for (std::uint32_t index = 0; index < unresolved_count; ++index) {
    Subject subject;
    subject.kind = reader.enum_value<SubjectKind>(7, "unresolved subject kind");
    subject.id = reader.u64();
    if (!reader.ok()) return reader.status();
    result.unresolved_subjects.push_back(subject);
  }
  const std::uint32_t explanation_count = reader.bounded_count(256, "result explanations");
  if (!reader.ok()) return reader.status();
  result.explanations.reserve(explanation_count);
  for (std::uint32_t index = 0; index < explanation_count; ++index) {
    Explanation explanation;
    const Status status = decode_explanation(reader, limits.model, &explanation);
    if (!status.ok()) return status;
    result.explanations.push_back(std::move(explanation));
  }
  result.request_digest = decode_digest(reader);
  if (!reader.ok()) return reader.status();
  const Status status = reader.require_end();
  if (!status.ok()) return status;
  return result;
}

std::vector<std::uint8_t> encode_validate_request_payload(const PlanRequest& request,
                                                          const RecoveryPlan& plan) {
  CanonicalWriter writer;
  request.encode(writer);
  encode_plan(plan, writer);
  encode_digest(writer, plan.plan_digest);
  return writer.take();
}

Result<std::pair<PlanRequest, RecoveryPlan>> decode_validate_request_payload(
    const std::vector<std::uint8_t>& payload, const ProtocolLimits& limits) {
  CanonicalReader reader(payload);
  PlanRequest request;
  Status status = decode_plan_request_body(reader, limits.model, &request);
  if (!status.ok()) return status;
  RecoveryPlan plan;
  status = decode_plan(reader, limits.model, &plan);
  if (!status.ok()) return status;
  plan.plan_digest = decode_digest(reader);
  if (!reader.ok()) return reader.status();
  status = reader.require_end();
  if (!status.ok()) return status;
  return std::make_pair(std::move(request), std::move(plan));
}

std::vector<std::uint8_t> encode_validate_response_payload(const ValidationReport& report) {
  CanonicalWriter writer;
  writer.boolean(report.valid);
  writer.boolean(report.objective_matches);
  writer.boolean(report.digest_matches);
  report.recomputed_objective.encode(writer);
  encode_digest(writer, report.stated_plan_digest);
  encode_digest(writer, report.recomputed_plan_digest);
  writer.u32(static_cast<std::uint32_t>(report.findings.size()));
  for (const ValidationFinding& finding : report.findings) {
    writer.u8(static_cast<std::uint8_t>(finding.code));
    writer.u32(finding.step_index);
    writer.u8(static_cast<std::uint8_t>(finding.subject.kind));
    writer.u64(finding.subject.id);
    writer.str(finding.text);
  }
  return writer.take();
}

Result<ValidationReport> decode_validate_response_payload(const std::vector<std::uint8_t>& payload) {
  CanonicalReader reader(payload);
  ValidationReport report;
  report.valid = reader.boolean();
  report.objective_matches = reader.boolean();
  report.digest_matches = reader.boolean();
  for (std::size_t component = 0; component < kObjectiveComponents; ++component) {
    report.recomputed_objective[component] = reader.u64();
  }
  report.stated_plan_digest = decode_digest(reader);
  report.recomputed_plan_digest = decode_digest(reader);
  const std::uint32_t finding_count = reader.bounded_count(512, "validation findings");
  if (!reader.ok()) return reader.status();
  report.findings.reserve(finding_count);
  for (std::uint32_t index = 0; index < finding_count; ++index) {
    ValidationFinding finding;
    finding.code = reader.enum_value<ReasonCode>(static_cast<std::uint8_t>(ReasonCode::COUNT),
                                                 "finding reason");
    finding.step_index = reader.u32();
    finding.subject.kind = reader.enum_value<SubjectKind>(7, "finding subject kind");
    finding.subject.id = reader.u64();
    finding.text = reader.str(512);
    if (!reader.ok()) return reader.status();
    report.findings.push_back(std::move(finding));
  }
  const Status status = reader.require_end();
  if (!status.ok()) return status;
  return report;
}

std::vector<std::uint8_t> encode_status_response_payload(Epoch epoch,
                                                         BootId boot,
                                                         Sequence last_sequence,
                                                         std::uint64_t plans_committed,
                                                         std::uint64_t sessions_active,
                                                         std::uint64_t plans_rejected) {
  CanonicalWriter writer;
  writer.u64(epoch.value());
  writer.u64(boot.value());
  writer.u64(last_sequence.value);
  writer.u64(plans_committed);
  writer.u64(sessions_active);
  writer.u64(plans_rejected);
  return writer.take();
}

}  // namespace nrp
