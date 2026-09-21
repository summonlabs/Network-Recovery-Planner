// Network Recovery Planner - framed multi-threaded server.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "nrp/runtime.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace nrp {
namespace {

#ifdef _WIN32
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;
#else
using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;
#endif

struct ErrorMapping {
  ErrorCode code = ErrorCode::DECODE_REJECTED;
  ReasonCode reason = ReasonCode::PROTOCOL_DECODE_REJECTED;
};

ErrorMapping map_status(const Status& status) {
  ErrorMapping mapping;
  switch (status.code()) {
    case StatusCode::PROTOCOL_ERROR:
      mapping.code = ErrorCode::DECODE_REJECTED;
      mapping.reason = ReasonCode::PROTOCOL_DECODE_REJECTED;
      break;
    case StatusCode::UNSUPPORTED:
      mapping.code = ErrorCode::UNSUPPORTED_REQUEST;
      mapping.reason = ReasonCode::REQUEST_UNSUPPORTED_PROBLEM;
      break;
    case StatusCode::OUT_OF_RANGE:
      mapping.code = ErrorCode::FRAME_TOO_LARGE;
      mapping.reason = ReasonCode::PROTOCOL_FRAME_TOO_LARGE;
      break;
    case StatusCode::STATE_MISMATCH:
      mapping.code = ErrorCode::SEQUENCE_REGRESSION;
      mapping.reason = ReasonCode::PROTOCOL_SEQUENCE_REGRESSION;
      break;
    case StatusCode::EXHAUSTED:
      mapping.code = ErrorCode::QUEUE_LIMIT;
      mapping.reason = ReasonCode::QUEUE_LIMIT_REACHED;
      break;
    case StatusCode::CLOSED:
      mapping.code = ErrorCode::SHUTTING_DOWN;
      mapping.reason = ReasonCode::SHUTDOWN_REQUESTED;
      break;
    case StatusCode::CORRUPT:
    case StatusCode::INVALID_ARGUMENT:
    case StatusCode::IO_ERROR:
    case StatusCode::NOT_FOUND:
    case StatusCode::CONFLICT:
    case StatusCode::OK:
      mapping.code = ErrorCode::DECODE_REJECTED;
      mapping.reason = ReasonCode::PROTOCOL_DECODE_REJECTED;
      break;
  }
  return mapping;
}

}  // namespace

struct PlanningServer::Impl {
  std::shared_ptr<PlannerService> service;
  ServerConfig config;
  ProtocolLimits limits{};
  Epoch epoch;
  BootId boot;

  std::atomic<bool> stopping{false};
  transport::Socket listener;
  std::uint16_t port = 0;

  std::thread accept_thread;
  std::mutex connections_mutex;
  std::vector<std::shared_ptr<transport::Socket>> connections;
  std::vector<std::thread> connection_threads;

  std::unique_ptr<SessionRegistry> sessions;

  std::atomic<std::uint64_t> connections_accepted{0};
  std::atomic<std::uint64_t> connections_rejected{0};
  std::atomic<std::uint64_t> frames_received{0};
  std::atomic<std::uint64_t> frames_rejected{0};
  std::atomic<std::uint64_t> sticky_failures{0};

  void accept_loop();
  void serve(const std::shared_ptr<transport::Socket>& socket);
  Status send_frame(transport::Socket& socket,
                    FrameType type,
                    SessionId session,
                    Sequence sequence,
                    const std::vector<std::uint8_t>& payload);
  Status send_error(transport::Socket& socket,
                    SessionId session,
                    Sequence sequence,
                    ErrorCode code,
                    ReasonCode reason,
                    const std::string& text);
};

Status PlanningServer::Impl::send_frame(transport::Socket& socket,
                                        FrameType type,
                                        SessionId session,
                                        Sequence sequence,
                                        const std::vector<std::uint8_t>& payload) {
  const std::vector<std::uint8_t> bytes =
      encode_frame(type, session.value(), epoch, boot, sequence, payload);
  return socket.send_all(bytes.data(), bytes.size());
}

Status PlanningServer::Impl::send_error(transport::Socket& socket,
                                        SessionId session,
                                        Sequence sequence,
                                        ErrorCode code,
                                        ReasonCode reason,
                                        const std::string& text) {
  return send_frame(socket, FrameType::ERROR_FRAME, session, sequence,
                    encode_error_payload(code, reason, text));
}

void PlanningServer::Impl::accept_loop() {
  const NativeSocket listener_handle = static_cast<NativeSocket>(listener.native_handle());
  while (!stopping.load()) {
    sockaddr_storage address{};
    int length = static_cast<int>(sizeof(address));
    const NativeSocket handle =
        ::accept(listener_handle, reinterpret_cast<sockaddr*>(&address), &length);
    if (handle == kInvalidSocket) {
      if (stopping.load()) break;
      continue;  // the listener is still valid; accept blocks again
    }
    std::shared_ptr<transport::Socket> socket =
        std::make_shared<transport::Socket>(std::move(transport::Socket::adopt(
            static_cast<std::uintptr_t>(handle)).value()));
    {
      std::lock_guard<std::mutex> guard(connections_mutex);
      if (stopping.load()) {
        socket->close();
        break;
      }
      if (sessions->size() >= config.max_sessions) {
        connections_rejected.fetch_add(1);
        (void)send_error(*socket, SessionId{}, Sequence{1}, ErrorCode::SESSION_LIMIT,
                         ReasonCode::SESSION_LIMIT_REACHED, "session limit reached");
        socket->close();
        continue;
      }
      connections.push_back(socket);
    }
    connections_accepted.fetch_add(1);
    // Threads are joined at shutdown; the socket list is bounded by max_sessions.
    connection_threads.emplace_back([this, socket] { serve(socket); });
  }
}

void PlanningServer::Impl::serve(const std::shared_ptr<transport::Socket>& socket) {
  std::vector<std::uint8_t> buffer;
  buffer.reserve(1 << 16);
  // The receive chunk is heap allocated: a 16 KiB array on the stack of every
  // connection thread is exactly the kind of resource growth this runtime avoids.
  std::vector<std::uint8_t> chunk(16 * 1024);
  SessionId session{};
  Sequence server_sequence{};
  bool handshake_complete = false;
  bool sticky = false;

  while (!stopping.load() && !sticky) {
    // Read until at least one whole frame is buffered.
    bool need_more = true;
    while (need_more && !stopping.load()) {
      if (buffer.size() >= kFrameHeaderSize) {
        const Result<FrameHeader> header =
            decode_frame_header(buffer.data(), buffer.size());
        if (!header.ok()) {
          sticky = true;
          frames_rejected.fetch_add(1);
          sticky_failures.fetch_add(1);
          (void)send_error(*socket, session, Sequence{server_sequence.value + 1},
                           map_status(header.status()).code,
                           map_status(header.status()).reason, header.status().message());
          break;
        }
        if (header.value().payload_length > limits.max_payload_bytes) {
          sticky = true;
          frames_rejected.fetch_add(1);
          sticky_failures.fetch_add(1);
          (void)send_error(*socket, session, Sequence{server_sequence.value + 1},
                           ErrorCode::FRAME_TOO_LARGE, ReasonCode::PROTOCOL_FRAME_TOO_LARGE,
                           "declared payload exceeds the frame bound");
          break;
        }
        if (buffer.size() >= kFrameHeaderSize + header.value().payload_length) {
          need_more = false;
        }
      }
      if (!need_more) break;
      const Result<std::size_t> read = socket->recv_some(chunk.data(), chunk.size());
      if (!read.ok() || read.value() == 0) {
        // Peer closed or the socket was shut down for stopping: end the session.
        sticky = true;
        break;
      }
      buffer.insert(buffer.end(), chunk.begin(),
                    chunk.begin() + static_cast<std::ptrdiff_t>(read.value()));
      if (buffer.size() > limits.max_payload_bytes + 4 * kFrameHeaderSize) {
        sticky = true;
        frames_rejected.fetch_add(1);
        sticky_failures.fetch_add(1);
        break;
      }
    }
    if (sticky || stopping.load()) break;

    Frame frame;
    std::size_t consumed = 0;
    const Status decoded = decode_frame(buffer.data(), buffer.size(), limits, &frame, &consumed);
    if (!decoded.ok()) {
      sticky = true;
      frames_rejected.fetch_add(1);
      sticky_failures.fetch_add(1);
      const ErrorMapping mapping = map_status(decoded);
      (void)send_error(*socket, session, Sequence{server_sequence.value + 1}, mapping.code,
                       mapping.reason, decoded.message());
      break;
    }
    buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(consumed));
    frames_received.fetch_add(1);

    const FrameType type = static_cast<FrameType>(frame.header.type);
    if (!handshake_complete) {
      if (type != FrameType::HELLO) {
        sticky = true;
        sticky_failures.fetch_add(1);
        (void)send_error(*socket, SessionId{}, Sequence{1}, ErrorCode::SESSION_MISMATCH,
                         ReasonCode::PROTOCOL_SESSION_MISMATCH,
                         "the first frame of a connection must be HELLO");
        break;
      }
      const Result<std::uint64_t> nonce = decode_hello(frame.payload);
      if (!nonce.ok()) {
        sticky = true;
        sticky_failures.fetch_add(1);
        (void)send_error(*socket, SessionId{}, Sequence{1}, ErrorCode::DECODE_REJECTED,
                         ReasonCode::PROTOCOL_DECODE_REJECTED, nonce.status().message());
        break;
      }
      const Result<SessionRecord> created = sessions->create(epoch, boot, nonce.value());
      if (!created.ok()) {
        sticky = true;
        connections_rejected.fetch_add(1);
        (void)send_error(*socket, SessionId{}, Sequence{1}, ErrorCode::SESSION_LIMIT,
                         ReasonCode::SESSION_LIMIT_REACHED, created.status().message());
        break;
      }
      session = created.value().id;
      server_sequence = Sequence{1};
      handshake_complete = true;
      const Status sent =
          send_frame(*socket, FrameType::HELLO_ACK, session, server_sequence,
                     encode_hello_ack(session, epoch, boot, 1, Sequence{server_sequence.value + 1}));
      if (!sent.ok()) break;
      ++server_sequence.value;
      continue;
    }

    const Status accepted =
        sessions->accept(SessionId::from_value(frame.header.session_id),
                         Epoch::from_value(frame.header.epoch),
                         BootId::from_value(frame.header.boot),
                         Sequence{frame.header.sequence});
    if (!accepted.ok()) {
      sticky = true;
      sticky_failures.fetch_add(1);
      (void)send_error(*socket, session, Sequence{server_sequence.value + 1},
                       ErrorCode::SESSION_MISMATCH, ReasonCode::PROTOCOL_SESSION_MISMATCH,
                       accepted.message());
      break;
    }
    const Sequence response_sequence{server_sequence.value + 1};

    switch (type) {
      case FrameType::PLAN_REQUEST: {
        const Result<PlanRequest> request = decode_plan_request_payload(frame.payload, limits);
        if (!request.ok()) {
          sticky = true;
          sticky_failures.fetch_add(1);
          const ErrorMapping mapping = map_status(request.status());
          (void)send_error(*socket, session, response_sequence, mapping.code, mapping.reason,
                           request.status().message());
          break;
        }
        const Result<PlanningResult> result = service->plan(request.value());
        if (!result.ok()) {
          const ErrorMapping mapping = map_status(result.status());
          (void)send_error(*socket, session, response_sequence, mapping.code, mapping.reason,
                           result.status().message());
          ++server_sequence.value;
          break;
        }
        (void)send_frame(*socket, FrameType::PLAN_RESPONSE, session, response_sequence,
                         encode_plan_response_payload(result.value()));
        ++server_sequence.value;
        break;
      }
      case FrameType::VALIDATE_REQUEST: {
        const Result<std::pair<PlanRequest, RecoveryPlan>> decoded_request =
            decode_validate_request_payload(frame.payload, limits);
        if (!decoded_request.ok()) {
          sticky = true;
          sticky_failures.fetch_add(1);
          const ErrorMapping mapping = map_status(decoded_request.status());
          (void)send_error(*socket, session, response_sequence, mapping.code, mapping.reason,
                           decoded_request.status().message());
          break;
        }
        const Result<ValidationReport> report =
            service->validate(decoded_request.value().first, decoded_request.value().second);
        if (!report.ok()) {
          const ErrorMapping mapping = map_status(report.status());
          (void)send_error(*socket, session, response_sequence, mapping.code, mapping.reason,
                           report.status().message());
          ++server_sequence.value;
          break;
        }
        (void)send_frame(*socket, FrameType::VALIDATE_RESPONSE, session, response_sequence,
                         encode_validate_response_payload(report.value()));
        ++server_sequence.value;
        break;
      }
      case FrameType::STATUS_REQUEST: {
        const ServiceStats stats = service->stats();
        (void)send_frame(*socket, FrameType::STATUS_RESPONSE, session, response_sequence,
                         encode_status_response_payload(epoch, boot, service->last_durable_sequence(),
                                                        stats.plans_found + stats.plans_infeasible,
                                                        sessions->size(),
                                                        stats.requests_rejected));
        ++server_sequence.value;
        break;
      }
      case FrameType::BYE: {
        sticky = true;
        break;
      }
      default: {
        sticky = true;
        sticky_failures.fetch_add(1);
        (void)send_error(*socket, session, response_sequence, ErrorCode::UNSUPPORTED_REQUEST,
                         ReasonCode::REQUEST_UNSUPPORTED_PROBLEM,
                         "frame type is not accepted in this state");
        break;
      }
    }
  }

  if (handshake_complete) (void)sessions->release(session);
  socket->shutdown_both();
  socket->close();
  {
    std::lock_guard<std::mutex> guard(connections_mutex);
    connections.erase(std::remove(connections.begin(), connections.end(), socket),
                      connections.end());
  }
}

Result<std::unique_ptr<PlanningServer>> PlanningServer::start(
    std::shared_ptr<PlannerService> service, const ServerConfig& config) {
  if (service == nullptr) {
    return Status::error(StatusCode::INVALID_ARGUMENT, "server requires a planner service");
  }
  const Status initialised = transport::ensure_network_initialised();
  if (!initialised.ok()) return initialised;

  std::unique_ptr<PlanningServer> server(new PlanningServer());
  server->impl_ = std::make_unique<Impl>();
  Impl& impl = *server->impl_;
  impl.service = std::move(service);
  impl.config = config;
  impl.epoch = impl.service->epoch();
  impl.boot = impl.service->boot();
  impl.sessions = std::make_unique<SessionRegistry>(config.max_sessions ? config.max_sessions : 1);

  const NativeSocket handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (handle == kInvalidSocket) {
    return Status::error(StatusCode::IO_ERROR, "cannot create the listening socket");
  }
  impl.listener = std::move(transport::Socket::adopt(static_cast<std::uintptr_t>(handle)).value());
  int reuse = 1;
  (void)::setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse),
                     sizeof(reuse));
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(config.port);
  if (::inet_pton(AF_INET, config.bind_address.c_str(), &address.sin_addr) != 1) {
    return Status::error(StatusCode::INVALID_ARGUMENT, "bind address is not a valid IPv4 address");
  }
  if (::bind(handle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    return Status::error(StatusCode::IO_ERROR, "bind failed");
  }
  if (::listen(handle, static_cast<int>(config.backlog)) != 0) {
    return Status::error(StatusCode::IO_ERROR, "listen failed");
  }
  sockaddr_in bound{};
  int bound_length = static_cast<int>(sizeof(bound));
  if (::getsockname(handle, reinterpret_cast<sockaddr*>(&bound), &bound_length) == 0) {
    impl.port = ntohs(bound.sin_port);
  }
  impl.accept_thread = std::thread([&impl] { impl.accept_loop(); });
  return std::unique_ptr<PlanningServer>(server.release());
}

PlanningServer::~PlanningServer() {
  if (impl_) {
    (void)shutdown();
  }
}

std::uint16_t PlanningServer::port() const { return impl_->port; }

Status PlanningServer::shutdown() {
  Impl& impl = *impl_;
  if (impl.stopping.exchange(true)) return Status::success();
  // Release blocked accepts and blocked reads promptly: shutdown wakes recv, and
  // closing the listener wakes accept.
  impl.listener.shutdown_both();
  impl.listener.close();
  {
    std::lock_guard<std::mutex> guard(impl.connections_mutex);
    for (const std::shared_ptr<transport::Socket>& socket : impl.connections) {
      if (socket) socket->shutdown_both();
    }
  }
  if (impl.accept_thread.joinable()) impl.accept_thread.join();
  for (std::thread& thread : impl.connection_threads) {
    if (thread.joinable()) thread.join();
  }
  impl.connection_threads.clear();
  {
    std::lock_guard<std::mutex> guard(impl.connections_mutex);
    for (const std::shared_ptr<transport::Socket>& socket : impl.connections) {
      if (socket) socket->close();
    }
    impl.connections.clear();
  }
  return Status::success();
}

ServerStats PlanningServer::stats() const {
  const Impl& impl = *impl_;
  ServerStats stats;
  stats.connections_accepted = impl.connections_accepted.load();
  stats.connections_rejected = impl.connections_rejected.load();
  stats.frames_received = impl.frames_received.load();
  stats.frames_rejected = impl.frames_rejected.load();
  stats.sticky_failures = impl.sticky_failures.load();
  return stats;
}

}  // namespace nrp
