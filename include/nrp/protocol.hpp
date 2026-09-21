// Network Recovery Planner - bounded framed transport protocol.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef NRP_PROTOCOL_HPP
#define NRP_PROTOCOL_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "nrp/domain.hpp"
#include "nrp/plan.hpp"
#include "nrp/result.hpp"
#include "nrp/validate.hpp"
#include "nrp/version.hpp"

namespace nrp {

inline constexpr std::uint32_t kFrameMagic = 0x4E525046u;  // 'NRPF'
inline constexpr std::size_t kFrameHeaderSize = 56;

/// Frame types. Unknown or reserved values are rejected, never ignored.
enum class FrameType : std::uint16_t {
  HELLO = 1,
  HELLO_ACK = 2,
  PLAN_REQUEST = 3,
  PLAN_RESPONSE = 4,
  VALIDATE_REQUEST = 5,
  VALIDATE_RESPONSE = 6,
  STATUS_REQUEST = 7,
  STATUS_RESPONSE = 8,
  BYE = 9,
  /// Named ERROR_FRAME because a public header may not collide with the
  /// platform macro ERROR from wingdi.h.
  ERROR_FRAME = 10,
  COUNT = 11,
};

const char* to_string(FrameType type) noexcept;
bool is_valid(FrameType type) noexcept;

enum class ErrorCode : std::uint16_t {
  NONE = 0,
  BAD_MAGIC = 1,
  BAD_VERSION = 2,
  BAD_HEADER_CHECKSUM = 3,
  BAD_PAYLOAD_CHECKSUM = 4,
  FRAME_TOO_LARGE = 5,
  INVALID_ENUM = 6,
  INVALID_LENGTH = 7,
  TRAILING_BYTES = 8,
  SEQUENCE_REGRESSION = 9,
  SESSION_MISMATCH = 10,
  SESSION_LIMIT = 11,
  QUEUE_LIMIT = 12,
  UNSUPPORTED_REQUEST = 13,
  DECODE_REJECTED = 14,
  STICKY_FAILURE = 15,
  SHUTTING_DOWN = 16,
  COUNT = 17,
};

const char* to_string(ErrorCode code) noexcept;
bool is_valid(ErrorCode code) noexcept;

/// Wire header. Fixed width, little endian, integrity checked twice: once for
/// the header itself and once for the payload, so a truncated or mutated frame
/// is always detected before any payload byte is interpreted.
struct FrameHeader {
  std::uint32_t magic = kFrameMagic;
  std::uint16_t version = kProtocolVersion;
  std::uint16_t type = 0;
  std::uint16_t flags = 0;
  std::uint16_t reserved = 0;
  std::uint64_t session_id = 0;
  std::uint64_t epoch = 0;
  std::uint64_t boot = 0;
  std::uint64_t sequence = 0;
  std::uint32_t payload_length = 0;
  std::uint32_t payload_crc32 = 0;
  std::uint32_t header_crc32 = 0;
};

void encode_frame_header(const FrameHeader& header, std::uint8_t out[kFrameHeaderSize]);
Result<FrameHeader> decode_frame_header(const std::uint8_t* bytes, std::size_t size);

/// A decoded frame: validated header plus validated payload bytes.
struct Frame {
  FrameHeader header{};
  std::vector<std::uint8_t> payload;
};

/// Bounds enforced before any allocation happens.
struct ProtocolLimits {
  std::uint32_t max_payload_bytes = 4u << 20;  // 4 MiB
  std::uint32_t max_records_per_message = 4096;
  ModelLimits model{};
};

/// Encodes a frame including header checksum and payload checksum.
std::vector<std::uint8_t> encode_frame(FrameType type,
                                       std::uint64_t session_id,
                                       Epoch epoch,
                                       BootId boot,
                                       Sequence sequence,
                                       const std::vector<std::uint8_t>& payload);

/// Decodes one frame from a byte buffer. Returns the number of bytes consumed
/// via *consumed on success. Failure is sticky at the connection level: callers
/// must close the connection instead of resynchronising.
Status decode_frame(const std::uint8_t* data,
                    std::size_t size,
                    const ProtocolLimits& limits,
                    Frame* out,
                    std::size_t* consumed);

// ---------------------------------------------------------------------------
// Payload codecs
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> encode_hello(std::uint64_t client_nonce, std::uint32_t requested_features);
Result<std::uint64_t> decode_hello(const std::vector<std::uint8_t>& payload);

std::vector<std::uint8_t> encode_hello_ack(SessionId session,
                                           Epoch epoch,
                                           BootId boot,
                                           std::uint64_t server_nonce,
                                           Sequence next_sequence);
struct HelloAck {
  SessionId session{};
  Epoch epoch{};
  BootId boot{};
  std::uint64_t server_nonce = 0;
  Sequence next_sequence{};
};
Result<HelloAck> decode_hello_ack(const std::vector<std::uint8_t>& payload);

std::vector<std::uint8_t> encode_error_payload(ErrorCode code, ReasonCode reason, std::string_view text);
struct ErrorPayload {
  ErrorCode code = ErrorCode::NONE;
  ReasonCode reason = ReasonCode::NONE;
  std::string text;
};
Result<ErrorPayload> decode_error_payload(const std::vector<std::uint8_t>& payload);

std::vector<std::uint8_t> encode_plan_request_payload(const PlanRequest& request);
Result<PlanRequest> decode_plan_request_payload(const std::vector<std::uint8_t>& payload,
                                                const ProtocolLimits& limits);

std::vector<std::uint8_t> encode_plan_response_payload(const PlanningResult& result);
Result<PlanningResult> decode_plan_response_payload(const std::vector<std::uint8_t>& payload,
                                                    const ProtocolLimits& limits);

std::vector<std::uint8_t> encode_validate_request_payload(const PlanRequest& request,
                                                          const RecoveryPlan& plan);
Result<std::pair<PlanRequest, RecoveryPlan>> decode_validate_request_payload(
    const std::vector<std::uint8_t>& payload, const ProtocolLimits& limits);

std::vector<std::uint8_t> encode_validate_response_payload(const ValidationReport& report);
Result<ValidationReport> decode_validate_response_payload(const std::vector<std::uint8_t>& payload);

std::vector<std::uint8_t> encode_status_response_payload(Epoch epoch,
                                                         BootId boot,
                                                         Sequence last_sequence,
                                                         std::uint64_t plans_committed,
                                                         std::uint64_t sessions_active,
                                                         std::uint64_t plans_rejected);

}  // namespace nrp

#endif  // NRP_PROTOCOL_HPP
