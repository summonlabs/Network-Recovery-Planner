// Network Recovery Planner - framed protocol client.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "nrp/runtime.hpp"

#include <atomic>
#include <cstring>
#include <vector>

namespace nrp {
namespace {

std::atomic<std::uint64_t> g_client_nonce{1};

}  // namespace

PlanningClient::~PlanningClient() {
  if (!closed_) (void)close();
}

Result<std::unique_ptr<PlanningClient>> PlanningClient::connect(const ClientConfig& config) {
  const Status initialised = transport::ensure_network_initialised();
  if (!initialised.ok()) return initialised;
  Result<transport::Socket> socket = transport::Socket::connect(config.host, config.port);
  if (!socket.ok()) return socket.status();

  std::unique_ptr<PlanningClient> client(new PlanningClient());
  client->socket_ = std::move(socket.value());
  client->limits_ = config.protocol_limits;
  client->client_sequence_ = Sequence{1};

  const std::uint64_t nonce = g_client_nonce.fetch_add(1) + 1;
  const std::vector<std::uint8_t> hello =
      encode_frame(FrameType::HELLO, 0, Epoch{}, BootId{}, Sequence{1}, encode_hello(nonce, 1));
  Status status = client->socket_.send_all(hello.data(), hello.size());
  if (!status.ok()) return status;

  std::vector<std::uint8_t> raw;
  status = client->read_frame_bytes(&raw);
  if (!status.ok()) return status;
  Frame frame;
  std::size_t consumed = 0;
  status = decode_frame(raw.data(), raw.size(), client->limits_, &frame, &consumed);
  if (!status.ok()) return status;
  if (static_cast<FrameType>(frame.header.type) != FrameType::HELLO_ACK) {
    return Status::error(StatusCode::PROTOCOL_ERROR, "server did not answer HELLO with HELLO_ACK");
  }
  const Result<HelloAck> ack = decode_hello_ack(frame.payload);
  if (!ack.ok()) return ack.status();
  client->session_ = ack.value().session;
  client->epoch_ = ack.value().epoch;
  client->boot_ = ack.value().boot;
  client->handshake_complete_ = true;
  client->server_sequence_ = Sequence{0};
  return std::unique_ptr<PlanningClient>(client.release());
}

Status PlanningClient::read_frame_bytes(std::vector<std::uint8_t>* out) {
  out->clear();
  std::uint8_t header[kFrameHeaderSize];
  bool eof = false;
  Result<std::size_t> read = socket_.recv_exact_or_eof(header, kFrameHeaderSize, &eof);
  if (!read.ok()) return read.status();
  if (eof) return Status::error(StatusCode::CLOSED, "peer closed before a frame header arrived");
  const Result<FrameHeader> decoded = decode_frame_header(header, kFrameHeaderSize);
  if (!decoded.ok()) return decoded.status();
  if (decoded.value().payload_length > limits_.max_payload_bytes) {
    return Status::error(StatusCode::OUT_OF_RANGE, "declared payload exceeds the frame bound");
  }
  out->assign(header, header + kFrameHeaderSize);
  if (decoded.value().payload_length > 0) {
    const std::size_t offset = out->size();
    out->resize(offset + decoded.value().payload_length);
    read = socket_.recv_exact_or_eof(out->data() + offset, decoded.value().payload_length, &eof);
    if (!read.ok()) return read.status();
    if (eof) return Status::error(StatusCode::CLOSED, "peer closed inside a frame payload");
  }
  return Status::success();
}

Status PlanningClient::send_request(FrameType type, const std::vector<std::uint8_t>& payload) {
  if (closed_) return Status::error(StatusCode::CLOSED, "client is closed");
  if (!handshake_complete_) {
    return Status::error(StatusCode::STATE_MISMATCH, "handshake has not completed");
  }
  const std::vector<std::uint8_t> bytes = encode_frame(type, session_.value(), epoch_, boot_,
                                                       client_sequence_, payload);
  Status status = socket_.send_all(bytes.data(), bytes.size());
  if (!status.ok()) return status;
  ++client_sequence_.value;
  return Status::success();
}

Status PlanningClient::read_response(FrameType expected, std::vector<std::uint8_t>* payload) {
  std::vector<std::uint8_t> raw;
  Status status = read_frame_bytes(&raw);
  if (!status.ok()) return status;
  Frame frame;
  std::size_t consumed = 0;
  status = decode_frame(raw.data(), raw.size(), limits_, &frame, &consumed);
  if (!status.ok()) return status;
  if (SessionId::from_value(frame.header.session_id) != session_ ||
      Epoch::from_value(frame.header.epoch) != epoch_ ||
      BootId::from_value(frame.header.boot) != boot_) {
    return Status::error(StatusCode::STATE_MISMATCH,
                         "response frame carries a different session authority");
  }
  if (Sequence{frame.header.sequence} <= server_sequence_) {
    return Status::error(StatusCode::STATE_MISMATCH, "response sequence is not strictly increasing");
  }
  server_sequence_ = Sequence{frame.header.sequence};
  const FrameType type = static_cast<FrameType>(frame.header.type);
  if (type == FrameType::ERROR_FRAME) {
    const Result<ErrorPayload> error = decode_error_payload(frame.payload);
    if (!error.ok()) return error.status();
    return Status::error(StatusCode::STATE_MISMATCH,
                         std::string("server error ") + to_string(error.value().code) + " (" +
                             to_string(error.value().reason) + "): " + error.value().text);
  }
  if (type != expected) {
    return Status::error(StatusCode::PROTOCOL_ERROR, "unexpected response frame type");
  }
  *payload = std::move(frame.payload);
  return Status::success();
}

Result<PlanningResult> PlanningClient::plan(const PlanRequest& request) {
  Status status = send_request(FrameType::PLAN_REQUEST, encode_plan_request_payload(request));
  if (!status.ok()) return status;
  std::vector<std::uint8_t> payload;
  status = read_response(FrameType::PLAN_RESPONSE, &payload);
  if (!status.ok()) return status;
  return decode_plan_response_payload(payload, limits_);
}

Result<ValidationReport> PlanningClient::validate(const PlanRequest& request,
                                                  const RecoveryPlan& plan) {
  Status status = send_request(FrameType::VALIDATE_REQUEST,
                               encode_validate_request_payload(request, plan));
  if (!status.ok()) return status;
  std::vector<std::uint8_t> payload;
  status = read_response(FrameType::VALIDATE_RESPONSE, &payload);
  if (!status.ok()) return status;
  return decode_validate_response_payload(payload);
}

Status PlanningClient::ping() {
  Status status = send_request(FrameType::STATUS_REQUEST, {});
  if (!status.ok()) return status;
  std::vector<std::uint8_t> payload;
  return read_response(FrameType::STATUS_RESPONSE, &payload);
}

Status PlanningClient::send_raw_bytes(const std::vector<std::uint8_t>& bytes) {
  return socket_.send_all(bytes.data(), bytes.size());
}

Result<std::vector<std::uint8_t>> PlanningClient::read_raw_frame(const ProtocolLimits& limits) {
  const ProtocolLimits saved = limits_;
  limits_ = limits;
  std::vector<std::uint8_t> raw;
  const Status status = read_frame_bytes(&raw);
  limits_ = saved;
  if (!status.ok()) return status;
  return raw;
}

Status PlanningClient::close() {
  if (closed_) return Status::success();
  closed_ = true;
  if (handshake_complete_) {
    const std::vector<std::uint8_t> bytes =
        encode_frame(FrameType::BYE, session_.value(), epoch_, boot_, client_sequence_, {});
    (void)socket_.send_all(bytes.data(), bytes.size());
  }
  socket_.shutdown_both();
  socket_.close();
  return Status::success();
}

}  // namespace nrp
