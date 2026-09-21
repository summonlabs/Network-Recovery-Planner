// Network Recovery Planner - sessions, worker service, framed server and client.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef NRP_RUNTIME_HPP
#define NRP_RUNTIME_HPP

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "nrp/persistence.hpp"
#include "nrp/plan.hpp"
#include "nrp/planner.hpp"
#include "nrp/protocol.hpp"
#include "nrp/validate.hpp"

namespace nrp {

// ---------------------------------------------------------------------------
// Fault injection (explicit, off by default)
// ---------------------------------------------------------------------------

/// Durable/lifecycle boundaries a host may deliberately crash at in order to
/// prove conservative recovery. NONE disables injection completely.
enum class CrashPoint : std::uint8_t {
  NONE = 0,
  AFTER_ATTEMPT_APPEND_BEFORE_FLUSH = 1,
  AFTER_COMMIT_BEFORE_PUBLISH = 2,
  AFTER_PUBLISH_BEFORE_ACK = 3,
  COUNT = 4,
};

const char* to_string(CrashPoint point) noexcept;
bool is_valid(CrashPoint point) noexcept;
/// Parses the documented NRP_FAULT_CRASH_POINT values; NONE for empty/absent.
Result<CrashPoint> parse_crash_point(const std::string& text);
/// Hard, immediate process termination at the configured boundary. Never
/// returns; runs no destructor and no flush other than the ones already issued.
void crash_now(CrashPoint point);

// ---------------------------------------------------------------------------
// Transport primitives (plain TCP, no transport security - see README)
// ---------------------------------------------------------------------------

namespace transport {

/// Blocking TCP socket. All failures are reported; no operation is retried
/// behind the caller's back and no timeout is ever applied implicitly.
class Socket {
 public:
  Socket() = default;
  ~Socket();
  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;

  static Result<Socket> connect(const std::string& host, std::uint16_t port);
  static Result<Socket> adopt(std::uintptr_t native_handle);

  bool valid() const noexcept;
  std::uintptr_t native_handle() const noexcept { return handle_; }

  Status send_all(const std::uint8_t* data, std::size_t size);
  /// Returns the number of bytes read; 0 means the peer closed cleanly.
  Result<std::size_t> recv_some(std::uint8_t* buffer, std::size_t capacity);
  Result<std::size_t> recv_exact_or_eof(std::uint8_t* buffer, std::size_t size, bool* eof);
  Status shutdown_both();
  void close() noexcept;

  std::string peer_description() const { return peer_; }
  void set_peer_description(std::string text) { peer_ = std::move(text); }

 private:
  std::uintptr_t handle_ = static_cast<std::uintptr_t>(~static_cast<std::uintptr_t>(0));
  std::string peer_;
};

/// One-time process level network initialisation (Winsock on Windows).
Status ensure_network_initialised();
void shutdown_network() noexcept;

}  // namespace transport

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

/// Established session authority. A frame is only accepted when it carries the
/// exact (session, epoch, boot) triple that was established at handshake time
/// and a strictly increasing sequence number.
struct SessionRecord {
  SessionId id{};
  Epoch epoch{};
  BootId boot{};
  Sequence last_client_sequence{};
  Sequence server_sequence{};
  std::uint64_t client_nonce = 0;
  std::uint64_t active_requests = 0;
  bool closed = false;
};

class SessionRegistry {
 public:
  explicit SessionRegistry(std::uint32_t max_sessions) : max_sessions_(max_sessions ? max_sessions : 1) {}

  Result<SessionRecord> create(Epoch epoch, BootId boot, std::uint64_t client_nonce);
  /// Validates the authority triple and the monotonic client sequence.
  Status accept(SessionId id, Epoch epoch, BootId boot, Sequence sequence);
  Status release(SessionId id);
  Result<SessionRecord> get(SessionId id) const;

  std::uint32_t size() const;
  std::uint32_t high_water() const;

 private:
  mutable std::mutex mutex_;
  std::vector<SessionRecord> sessions_;
  std::uint32_t max_sessions_;
  std::uint32_t high_water_ = 0;
  std::uint64_t next_id_ = 1;
};

// ---------------------------------------------------------------------------
// Worker service
// ---------------------------------------------------------------------------

struct ServiceConfig {
  ModelLimits model_limits{};
  ProtocolLimits protocol_limits{};
  StoreLimits store_limits{};
  std::uint32_t worker_threads = 4;
  std::uint32_t max_queue_depth = 256;
  std::uint32_t max_sessions = 64;
  CrashPoint crash_point = CrashPoint::NONE;
  bool persist = true;
};

struct ServiceStats {
  std::uint64_t requests_accepted = 0;
  std::uint64_t requests_completed = 0;
  std::uint64_t requests_rejected = 0;
  std::uint64_t requests_refused_exhausted = 0;
  std::uint64_t plans_found = 0;
  std::uint64_t plans_infeasible = 0;
  std::uint64_t plans_indeterminate = 0;
  std::uint64_t validations_run = 0;
  std::uint64_t queue_high_water = 0;
  std::uint64_t thread_count = 0;
};

/// Owns the durable store, the planner and a bounded worker pool. All public
/// methods are thread safe. Shutdown is idempotent, drains queued work with an
/// explicit CLOSED status and joins every worker before returning.
class PlannerService {
 public:
  static Result<std::shared_ptr<PlannerService>> start(const ServiceConfig& config,
                                                       const std::string& store_path);
  ~PlannerService();

  PlannerService(const PlannerService&) = delete;
  PlannerService& operator=(const PlannerService&) = delete;

  /// Submits and waits. Never blocks forever: shutdown completes outstanding
  /// jobs with a CLOSED status.
  Result<PlanningResult> plan(const PlanRequest& request);
  Result<ValidationReport> validate(const PlanRequest& request, const RecoveryPlan& plan);

  /// Asynchronous submission. The callback is invoked outside every internal
  /// lock and after the durable commit for the job has been flushed.
  Status submit_plan(const PlanRequest& request,
                     std::function<void(Result<PlanningResult>)> callback);

  Status shutdown();

  ServiceStats stats() const;
  Epoch epoch() const;
  BootId boot() const;
  Sequence last_durable_sequence() const;
  const RecoveryReport& recovery() const;
  DurableStore* store() const noexcept { return store_; }

 private:
  PlannerService() = default;
  struct Impl;
  std::unique_ptr<Impl> impl_;
  DurableStore* store_ = nullptr;
};

// ---------------------------------------------------------------------------
// Server / client
// ---------------------------------------------------------------------------

struct ServerConfig {
  std::string bind_address = "127.0.0.1";
  std::uint16_t port = 0;  // 0 selects an ephemeral port
  std::uint32_t max_sessions = 64;
  std::uint32_t backlog = 32;
};

struct ServerStats {
  std::uint64_t connections_accepted = 0;
  std::uint64_t connections_rejected = 0;
  std::uint64_t frames_received = 0;
  std::uint64_t frames_rejected = 0;
  std::uint64_t sticky_failures = 0;
};

/// Multi-threaded framed server. Request handling is delegated to the
/// PlannerService; the server itself owns no planning state.
class PlanningServer {
 public:
  static Result<std::unique_ptr<PlanningServer>> start(std::shared_ptr<PlannerService> service,
                                                       const ServerConfig& config);
  ~PlanningServer();

  PlanningServer(const PlanningServer&) = delete;
  PlanningServer& operator=(const PlanningServer&) = delete;

  /// Actual bound port (useful when config.port was 0).
  std::uint16_t port() const;
  /// Releases the listening socket and every blocked accept/read promptly, then
  /// joins all connection threads.
  Status shutdown();
  ServerStats stats() const;

 private:
  PlanningServer() = default;
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

struct ClientConfig {
  ProtocolLimits protocol_limits{};
  std::string host = "127.0.0.1";
  std::uint16_t port = 0;
};

class PlanningClient {
 public:
  static Result<std::unique_ptr<PlanningClient>> connect(const ClientConfig& config);
  ~PlanningClient();

  PlanningClient(const PlanningClient&) = delete;
  PlanningClient& operator=(const PlanningClient&) = delete;

  Result<PlanningResult> plan(const PlanRequest& request);
  Result<ValidationReport> validate(const PlanRequest& request, const RecoveryPlan& plan);
  Status ping();

  SessionId session() const noexcept { return session_; }
  Epoch epoch() const noexcept { return epoch_; }
  BootId boot() const noexcept { return boot_; }
  Sequence last_sequence() const noexcept { return client_sequence_; }

  /// Raw access for protocol adversarial testing: sends arbitrary bytes on the
  /// established connection and reads whatever the server answers.
  Status send_raw_bytes(const std::vector<std::uint8_t>& bytes);
  Result<std::vector<std::uint8_t>> read_raw_frame(const ProtocolLimits& limits);
  Status close();

  transport::Socket* socket() noexcept { return &socket_; }

 private:
  PlanningClient() = default;

  Status read_frame_bytes(std::vector<std::uint8_t>* out);
  Status send_request(FrameType type, const std::vector<std::uint8_t>& payload);
  Status read_response(FrameType expected, std::vector<std::uint8_t>* payload);

  transport::Socket socket_;
  ProtocolLimits limits_{};
  SessionId session_{};
  Epoch epoch_{};
  BootId boot_{};
  Sequence client_sequence_{};
  Sequence server_sequence_{};
  bool handshake_complete_ = false;
  bool closed_ = false;
};

}  // namespace nrp

#endif  // NRP_RUNTIME_HPP
