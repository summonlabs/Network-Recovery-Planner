// Network Recovery Planner - framed protocol adversarial tests.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include <string>
#include <vector>

#include "nrp/planner.hpp"
#include "nrp/protocol.hpp"
#include "support/fixture.hpp"
#include "support/test_support.hpp"

using namespace nrp;
using namespace nrp::test;

namespace {

std::vector<std::uint8_t> frame_bytes(FrameType type = FrameType::PLAN_REQUEST,
                                      const std::vector<std::uint8_t>& payload = {1, 2, 3}) {
  return encode_frame(type, 42, Epoch::from_value(3), BootId::from_value(4), Sequence{9}, payload);
}

}  // namespace

NRP_TEST(protocol, frame_round_trip_consumes_exactly_one_frame) {
  ProtocolLimits limits;
  const std::vector<std::uint8_t> first = frame_bytes();
  const std::vector<std::uint8_t> second = frame_bytes(FrameType::STATUS_REQUEST, {7});
  std::vector<std::uint8_t> stream = first;
  stream.insert(stream.end(), second.begin(), second.end());

  Frame frame;
  std::size_t consumed = 0;
  NRP_REQUIRE(decode_frame(stream.data(), stream.size(), limits, &frame, &consumed).ok());
  NRP_CHECK_EQ(consumed, first.size());
  NRP_CHECK_EQ(frame.header.session_id, 42ull);
  NRP_CHECK_EQ(frame.header.epoch, 3ull);
  NRP_CHECK_EQ(frame.header.boot, 4ull);
  NRP_CHECK_EQ(frame.header.sequence, 9ull);
  NRP_CHECK_EQ(frame.payload.size(), static_cast<std::size_t>(3));
  NRP_REQUIRE(decode_frame(stream.data() + consumed, stream.size() - consumed, limits, &frame,
                           &consumed)
                  .ok());
  NRP_CHECK_EQ(static_cast<int>(frame.header.type), static_cast<int>(FrameType::STATUS_REQUEST));
}

NRP_TEST(protocol, every_truncated_prefix_is_refused) {
  ProtocolLimits limits;
  const std::vector<std::uint8_t> bytes = frame_bytes(FrameType::HELLO, {9, 9, 9, 9, 9});
  for (std::size_t length = 0; length < bytes.size(); ++length) {
    Frame frame;
    std::size_t consumed = 0;
    const Status status = decode_frame(bytes.data(), length, limits, &frame, &consumed);
    NRP_CHECK_MSG(!status.ok(), "prefix of length " << length << " decoded as a whole frame");
    if (length < kFrameHeaderSize) {
      NRP_CHECK_EQ(static_cast<int>(status.code()), static_cast<int>(StatusCode::NOT_FOUND));
    }
  }
}

NRP_TEST(protocol, every_header_byte_corruption_is_detected) {
  ProtocolLimits limits;
  const std::vector<std::uint8_t> bytes = frame_bytes();
  for (std::size_t offset = 0; offset < kFrameHeaderSize; ++offset) {
    std::vector<std::uint8_t> corrupted = bytes;
    corrupted[offset] ^= 0x01;
    Frame frame;
    std::size_t consumed = 0;
    NRP_CHECK_MSG(!decode_frame(corrupted.data(), corrupted.size(), limits, &frame, &consumed).ok(),
                  "header corruption at offset " << offset << " was accepted");
  }
  for (std::size_t offset = kFrameHeaderSize; offset < bytes.size(); ++offset) {
    std::vector<std::uint8_t> corrupted = bytes;
    corrupted[offset] ^= 0x01;
    Frame frame;
    std::size_t consumed = 0;
    NRP_CHECK_MSG(!decode_frame(corrupted.data(), corrupted.size(), limits, &frame, &consumed).ok(),
                  "payload corruption at offset " << offset << " was accepted");
  }
}

NRP_TEST(protocol, declared_lengths_are_bounded_before_allocation) {
  ProtocolLimits limits;
  limits.max_payload_bytes = 16;
  FrameHeader header;
  header.type = static_cast<std::uint16_t>(FrameType::PLAN_REQUEST);
  header.payload_length = limits.max_payload_bytes + 1;
  header.payload_crc32 = 0;
  std::vector<std::uint8_t> bytes(kFrameHeaderSize, 0);
  encode_frame_header(header, bytes.data());
  Frame frame;
  std::size_t consumed = 0;
  const Status status = decode_frame(bytes.data(), bytes.size(), limits, &frame, &consumed);
  NRP_CHECK(!status.ok());
  NRP_CHECK_EQ(static_cast<int>(status.code()), static_cast<int>(StatusCode::OUT_OF_RANGE));

  // A zero length payload is legal and produces an empty payload.
  FrameHeader empty;
  empty.type = static_cast<std::uint16_t>(FrameType::STATUS_REQUEST);
  empty.payload_length = 0;
  empty.payload_crc32 = 0;
  std::vector<std::uint8_t> empty_bytes(kFrameHeaderSize, 0);
  encode_frame_header(empty, empty_bytes.data());
  NRP_CHECK(decode_frame(empty_bytes.data(), empty_bytes.size(), limits, &frame, &consumed).ok());
  NRP_CHECK(frame.payload.empty());
}

NRP_TEST(protocol, invalid_headers_are_refused) {
  ProtocolLimits limits;
  const auto attempt = [&limits](const FrameHeader& header, std::size_t size) {
    std::vector<std::uint8_t> bytes(size, 0);
    if (size >= kFrameHeaderSize) encode_frame_header(header, bytes.data());
    Frame frame;
    std::size_t consumed = 0;
    return decode_frame(bytes.data(), bytes.size(), limits, &frame, &consumed);
  };
  FrameHeader header;
  header.type = static_cast<std::uint16_t>(FrameType::PLAN_REQUEST);
  NRP_CHECK(attempt(header, kFrameHeaderSize).ok());

  FrameHeader bad_magic = header;
  NRP_CHECK(!attempt(bad_magic, kFrameHeaderSize - 1).ok());

  FrameHeader bad_version = header;
  bad_version.version = static_cast<std::uint16_t>(kProtocolVersion + 1);
  NRP_CHECK(!attempt(bad_version, kFrameHeaderSize).ok());

  FrameHeader zero_type = header;
  zero_type.type = 0;
  NRP_CHECK(!attempt(zero_type, kFrameHeaderSize).ok());

  FrameHeader out_of_domain = header;
  out_of_domain.type = static_cast<std::uint16_t>(FrameType::COUNT) + 5;
  NRP_CHECK(!attempt(out_of_domain, kFrameHeaderSize).ok());

  FrameHeader reserved = header;
  reserved.reserved = 1;
  NRP_CHECK(!attempt(reserved, kFrameHeaderSize).ok());

  FrameHeader flags = header;
  flags.flags = 1;
  NRP_CHECK(!attempt(flags, kFrameHeaderSize).ok());
}

NRP_TEST(protocol, payload_codecs_are_total) {
  ProtocolLimits limits;
  // Each payload is decoded with its own decoder: the frame type tag is what
  // selects a codec, so cross-decoding is not a meaningful attack surface.
  const std::vector<std::uint8_t> hello = encode_hello(7, 1);
  const std::vector<std::uint8_t> hello_ack = encode_hello_ack(
      SessionId::from_value(1), Epoch::from_value(2), BootId::from_value(3), 4, Sequence{2});
  const std::vector<std::uint8_t> error =
      encode_error_payload(ErrorCode::BAD_MAGIC, ReasonCode::PROTOCOL_BAD_MAGIC, "bad");
  const auto totality = [](const std::vector<std::uint8_t>& payload, const auto& decoder,
                           const char* what) {
    for (std::size_t length = 0; length < payload.size(); ++length) {
      const std::vector<std::uint8_t> truncated(
          payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(length));
      NRP_CHECK_MSG(!decoder(truncated).ok(), what << " accepted a prefix of length " << length);
    }
    std::vector<std::uint8_t> extended = payload;
    extended.push_back(0);
    NRP_CHECK_MSG(!decoder(extended).ok(), what << " accepted trailing bytes");
  };
  totality(hello, [](const std::vector<std::uint8_t>& bytes) { return decode_hello(bytes); },
           "hello");
  totality(hello_ack,
           [](const std::vector<std::uint8_t>& bytes) { return decode_hello_ack(bytes); },
           "hello_ack");
  totality(error,
           [](const std::vector<std::uint8_t>& bytes) { return decode_error_payload(bytes); },
           "error");
  // Semantic validation.
  NRP_CHECK(!decode_hello(encode_hello(0, 1)).ok());
  NRP_CHECK(!decode_hello_ack(encode_hello_ack(SessionId{}, Epoch::from_value(1),
                                               BootId::from_value(1), 1, Sequence{1}))
                 .ok());
  NRP_CHECK(!decode_hello_ack(encode_hello_ack(SessionId::from_value(1), Epoch::from_value(1),
                                               BootId::from_value(1), 1, Sequence{0}))
                 .ok());
  const std::vector<std::uint8_t> bad_error = encode_error_payload(
      static_cast<ErrorCode>(999), ReasonCode::PROTOCOL_BAD_MAGIC, "x");
  NRP_CHECK(!decode_error_payload(bad_error).ok());
  NRP_CHECK(!decode_error_payload({}).ok());
}

NRP_TEST(protocol, plan_request_and_response_payloads_round_trip) {
  ProtocolLimits limits;
  TeachingFabric fabric;
  const PlanRequest request = fabric.request();
  const std::vector<std::uint8_t> encoded = encode_plan_request_payload(request);
  const Result<PlanRequest> decoded =
      decode_plan_request_payload(encoded, limits);
  NRP_REQUIRE(decoded.ok());
  NRP_CHECK_EQ(decoded.value().digest(), request.digest());

  for (std::size_t length = 0; length < encoded.size(); ++length) {
    const std::vector<std::uint8_t> truncated(
        encoded.begin(), encoded.begin() + static_cast<std::ptrdiff_t>(length));
    NRP_CHECK_MSG(!decode_plan_request_payload(truncated, limits).ok(),
                  "truncated request payload of length " << length << " decoded");
  }
  std::vector<std::uint8_t> extended = encoded;
  extended.push_back(0x7F);
  NRP_CHECK(!decode_plan_request_payload(extended, limits).ok());

  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_REQUIRE(result.plan.has_value());
  const std::vector<std::uint8_t> response = encode_plan_response_payload(result);
  const Result<PlanningResult> decoded_response = decode_plan_response_payload(response, limits);
  NRP_REQUIRE(decoded_response.ok());
  NRP_CHECK(decoded_response.value().decision == result.decision);
  NRP_REQUIRE(decoded_response.value().plan.has_value());
  NRP_CHECK_EQ(decoded_response.value().plan->plan_digest, result.plan->plan_digest);
  NRP_CHECK_EQ(compare_objective(decoded_response.value().plan->objective, result.plan->objective),
               0);

  for (std::size_t length = 0; length < response.size(); ++length) {
    const std::vector<std::uint8_t> truncated(
        response.begin(), response.begin() + static_cast<std::ptrdiff_t>(length));
    NRP_CHECK_MSG(!decode_plan_response_payload(truncated, limits).ok(),
                  "truncated response payload of length " << length << " decoded");
  }

  const std::vector<std::uint8_t> validate_request =
      encode_validate_request_payload(request, *result.plan);
  const Result<std::pair<PlanRequest, RecoveryPlan>> decoded_validate =
      decode_validate_request_payload(validate_request, limits);
  NRP_REQUIRE(decoded_validate.ok());
  NRP_CHECK_EQ(decoded_validate.value().second.plan_digest, result.plan->plan_digest);
  for (std::size_t length = 0; length < validate_request.size(); ++length) {
    const std::vector<std::uint8_t> truncated(
        validate_request.begin(), validate_request.begin() + static_cast<std::ptrdiff_t>(length));
    NRP_CHECK(!decode_validate_request_payload(truncated, limits).ok());
  }

  const ValidationReport report = validate_plan(request, *result.plan);
  const std::vector<std::uint8_t> validate_response = encode_validate_response_payload(report);
  const Result<ValidationReport> decoded_report = decode_validate_response_payload(validate_response);
  NRP_REQUIRE(decoded_report.ok());
  NRP_CHECK_EQ(decoded_report.value().valid, report.valid);
  NRP_CHECK_EQ(decoded_report.value().findings.size(), report.findings.size());
}
