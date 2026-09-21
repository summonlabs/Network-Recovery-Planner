// Network Recovery Planner - transport primitives, sessions and worker service.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Locking discipline (audited, see docs/CONCURRENCY_AUDIT.md):
//   * the durable store mutex, the work queue mutex and the session registry
//     mutex are never held at the same time, so no lock order inversion exists;
//   * planning runs outside every internal lock;
//   * callbacks and condition variable notifications are delivered outside locks;
//   * worker threads are joined without holding any lock they could need.
#include "nrp/runtime.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>

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

// ---------------------------------------------------------------------------
// Fault injection
// ---------------------------------------------------------------------------

const char* to_string(CrashPoint point) noexcept {
  switch (point) {
    case CrashPoint::NONE: return "NONE";
    case CrashPoint::AFTER_ATTEMPT_APPEND_BEFORE_FLUSH:
      return "AFTER_ATTEMPT_APPEND_BEFORE_FLUSH";
    case CrashPoint::AFTER_COMMIT_BEFORE_PUBLISH: return "AFTER_COMMIT_BEFORE_PUBLISH";
    case CrashPoint::AFTER_PUBLISH_BEFORE_ACK: return "AFTER_PUBLISH_BEFORE_ACK";
    case CrashPoint::COUNT: return "COUNT";
  }
  return "UNRECOGNISED_CRASH_POINT";
}

bool is_valid(CrashPoint point) noexcept {
  return static_cast<std::uint8_t>(point) < static_cast<std::uint8_t>(CrashPoint::COUNT);
}

Result<CrashPoint> parse_crash_point(const std::string& text) {
  if (text.empty() || text == "NONE") return CrashPoint::NONE;
  if (text == "AFTER_ATTEMPT_APPEND_BEFORE_FLUSH") {
    return CrashPoint::AFTER_ATTEMPT_APPEND_BEFORE_FLUSH;
  }
  if (text == "AFTER_COMMIT_BEFORE_PUBLISH") return CrashPoint::AFTER_COMMIT_BEFORE_PUBLISH;
  if (text == "AFTER_PUBLISH_BEFORE_ACK") return CrashPoint::AFTER_PUBLISH_BEFORE_ACK;
  return Status::error(StatusCode::INVALID_ARGUMENT, "unknown crash point: " + text);
}

void crash_now(CrashPoint point) {
  std::fprintf(stderr, "NRP_FAULT_INJECTED_CRASH %s\n", to_string(point));
  std::fflush(stderr);
  // Hard, immediate termination: no destructor runs and nothing is flushed
  // beyond what the durable store already flushed.
  std::_Exit(70);
}

namespace transport {
namespace {

#ifdef _WIN32
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;
#else
using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;
#endif

std::once_flag g_network_once;
Status g_network_status = Status::success();

void initialise_network_once() {
#ifdef _WIN32
  WSADATA data{};
  const int result = WSAStartup(MAKEWORD(2, 2), &data);
  if (result != 0) {
    g_network_status = Status::error(StatusCode::IO_ERROR, "WSAStartup failed");
  }
#else
  g_network_status = Status::success();
#endif
}

}  // namespace

Status ensure_network_initialised() {
  std::call_once(g_network_once, initialise_network_once);
  return g_network_status;
}

void shutdown_network() noexcept {
#ifdef _WIN32
  WSACleanup();
#endif
}

Socket::~Socket() { close(); }

Socket::Socket(Socket&& other) noexcept : handle_(other.handle_), peer_(std::move(other.peer_)) {
  other.handle_ = static_cast<std::uintptr_t>(kInvalidSocket);
  other.peer_.clear();
}

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    peer_ = std::move(other.peer_);
    other.handle_ = static_cast<std::uintptr_t>(kInvalidSocket);
    other.peer_.clear();
  }
  return *this;
}

bool Socket::valid() const noexcept { return handle_ != static_cast<std::uintptr_t>(kInvalidSocket); }

Result<Socket> Socket::connect(const std::string& host, std::uint16_t port) {
  const Status initialised = ensure_network_initialised();
  if (!initialised.ok()) return initialised;
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  addrinfo* results = nullptr;
  const std::string service = std::to_string(port);
  if (getaddrinfo(host.c_str(), service.c_str(), &hints, &results) != 0 || results == nullptr) {
    return Status::error(StatusCode::IO_ERROR, "cannot resolve " + host);
  }
  Status last = Status::error(StatusCode::IO_ERROR, "no address could be connected");
  for (addrinfo* entry = results; entry != nullptr; entry = entry->ai_next) {
    const NativeSocket handle = ::socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
    if (handle == kInvalidSocket) continue;
    if (::connect(handle, entry->ai_addr, static_cast<int>(entry->ai_addrlen)) == 0) {
      Socket socket;
      socket.handle_ = static_cast<std::uintptr_t>(handle);
      socket.peer_ = host + ":" + service;
      freeaddrinfo(results);
      return socket;
    }
    last = Status::error(StatusCode::IO_ERROR, "connect failed for " + host + ":" + service);
#ifdef _WIN32
    closesocket(handle);
#else
    ::close(handle);
#endif
  }
  freeaddrinfo(results);
  return last;
}

Result<Socket> Socket::adopt(std::uintptr_t native_handle) {
  Socket socket;
  socket.handle_ = native_handle;
  return socket;
}

Status Socket::send_all(const std::uint8_t* data, std::size_t size) {
  if (!valid()) return Status::error(StatusCode::CLOSED, "socket is not open");
  std::size_t sent = 0;
  while (sent < size) {
    const int chunk = static_cast<int>(std::min<std::size_t>(size - sent, 1u << 20));
    const int result = ::send(static_cast<NativeSocket>(handle_),
                              reinterpret_cast<const char*>(data + sent), chunk, 0);
    if (result <= 0) return Status::error(StatusCode::IO_ERROR, "send failed");
    sent += static_cast<std::size_t>(result);
  }
  return Status::success();
}

Result<std::size_t> Socket::recv_some(std::uint8_t* buffer, std::size_t capacity) {
  if (!valid()) return Status::error(StatusCode::CLOSED, "socket is not open");
  const int result = ::recv(static_cast<NativeSocket>(handle_),
                            reinterpret_cast<char*>(buffer),
                            static_cast<int>(std::min<std::size_t>(capacity, 1u << 20)), 0);
  if (result < 0) return Status::error(StatusCode::IO_ERROR, "recv failed");
  return static_cast<std::size_t>(result);
}

Result<std::size_t> Socket::recv_exact_or_eof(std::uint8_t* buffer,
                                              std::size_t size,
                                              bool* eof) {
  std::size_t received = 0;
  *eof = false;
  while (received < size) {
    const Result<std::size_t> chunk = recv_some(buffer + received, size - received);
    if (!chunk.ok()) return chunk.status();
    if (chunk.value() == 0) {
      *eof = true;
      return received;
    }
    received += chunk.value();
  }
  return received;
}

Status Socket::shutdown_both() {
  if (!valid()) return Status::error(StatusCode::CLOSED, "socket is not open");
#ifdef _WIN32
  ::shutdown(static_cast<NativeSocket>(handle_), SD_BOTH);
#else
  ::shutdown(static_cast<NativeSocket>(handle_), SHUT_RDWR);
#endif
  return Status::success();
}

void Socket::close() noexcept {
  if (!valid()) return;
  const NativeSocket handle = static_cast<NativeSocket>(handle_);
#ifdef _WIN32
  closesocket(handle);
#else
  ::close(handle);
#endif
  handle_ = static_cast<std::uintptr_t>(kInvalidSocket);
}

}  // namespace transport

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

Result<SessionRecord> SessionRegistry::create(Epoch epoch, BootId boot, std::uint64_t client_nonce) {
  std::lock_guard<std::mutex> guard(mutex_);
  SessionRecord* slot = nullptr;
  for (SessionRecord& candidate : sessions_) {
    if (candidate.closed) {
      slot = &candidate;
      break;
    }
  }
  if (slot == nullptr) {
    if (sessions_.size() >= max_sessions_) {
      return Status::error(StatusCode::EXHAUSTED, "session table is full");
    }
    sessions_.emplace_back();
    slot = &sessions_.back();
    if (sessions_.size() > high_water_) {
      high_water_ = static_cast<std::uint32_t>(sessions_.size());
    }
  }
  slot->id = SessionId::from_value(next_id_++);
  slot->epoch = epoch;
  slot->boot = boot;
  slot->client_nonce = client_nonce;
  slot->last_client_sequence = Sequence{0};
  slot->server_sequence = Sequence{0};
  slot->active_requests = 0;
  slot->closed = false;
  return *slot;
}

Status SessionRegistry::accept(SessionId id, Epoch epoch, BootId boot, Sequence sequence) {
  std::lock_guard<std::mutex> guard(mutex_);
  for (SessionRecord& record : sessions_) {
    if (record.id != id || record.closed) continue;
    if (record.epoch != epoch || record.boot != boot) {
      return Status::error(StatusCode::STATE_MISMATCH,
                           "frame authority does not match the established session");
    }
    if (sequence <= record.last_client_sequence) {
      return Status::error(StatusCode::STATE_MISMATCH,
                           "frame sequence is not strictly increasing");
    }
    record.last_client_sequence = sequence;
    ++record.active_requests;
    return Status::success();
  }
  return Status::error(StatusCode::NOT_FOUND, "session is not established");
}

Status SessionRegistry::release(SessionId id) {
  std::lock_guard<std::mutex> guard(mutex_);
  for (SessionRecord& record : sessions_) {
    if (record.id != id) continue;
    record.closed = true;
    record.active_requests = 0;
    return Status::success();
  }
  return Status::error(StatusCode::NOT_FOUND, "session is not established");
}

Result<SessionRecord> SessionRegistry::get(SessionId id) const {
  std::lock_guard<std::mutex> guard(mutex_);
  for (const SessionRecord& record : sessions_) {
    if (record.id == id && !record.closed) return record;
  }
  return Status::error(StatusCode::NOT_FOUND, "session is not established");
}

std::uint32_t SessionRegistry::size() const {
  std::lock_guard<std::mutex> guard(mutex_);
  std::uint32_t count = 0;
  for (const SessionRecord& record : sessions_) {
    if (!record.closed) ++count;
  }
  return count;
}

std::uint32_t SessionRegistry::high_water() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return high_water_;
}

// ---------------------------------------------------------------------------
// Worker service
// ---------------------------------------------------------------------------

namespace {

/// Handoff slot between a submitting thread and a worker thread.
struct JobState {
  std::mutex mutex;
  std::condition_variable cv;
  bool done = false;
  Status status = Status::error(StatusCode::CLOSED, "job did not complete");
  PlanningResult plan_result;
  ValidationReport validation_result;
};

}  // namespace

struct PlannerService::Impl {
  struct Job {
    enum class Kind : std::uint8_t { PLAN = 0, VALIDATE = 1 };
    Kind kind = Kind::PLAN;
    PlanRequest request;
    RecoveryPlan plan;
    std::function<void(Result<PlanningResult>)> callback;
    std::shared_ptr<JobState> state;
  };

  ServiceConfig config;
  std::string store_path;
  std::unique_ptr<DurableStore> store;
  std::unique_ptr<Planner> planner;
  std::unique_ptr<SessionRegistry> sessions;

  mutable std::mutex queue_mutex;
  std::condition_variable queue_cv;
  std::deque<Job> queue;
  bool stopping = false;

  mutable std::mutex durable_mutex;

  std::atomic<std::uint64_t> requests_accepted{0};
  std::atomic<std::uint64_t> requests_completed{0};
  std::atomic<std::uint64_t> requests_rejected{0};
  std::atomic<std::uint64_t> requests_refused_exhausted{0};
  std::atomic<std::uint64_t> plans_found{0};
  std::atomic<std::uint64_t> plans_infeasible{0};
  std::atomic<std::uint64_t> plans_indeterminate{0};
  std::atomic<std::uint64_t> validations_run{0};
  std::atomic<std::uint64_t> queue_high_water{0};

  std::vector<std::thread> workers;
  RecoveryReport recovery;
  Epoch epoch;
  BootId boot;
  Sequence last_durable_sequence;

  void worker_loop();
  Status append_durable(RecordType type, const std::vector<std::uint8_t>& payload);
  PlanningResult run_plan(const PlanRequest& request);
  ValidationReport run_validate(const PlanRequest& request, const RecoveryPlan& plan);
  void complete(Job& job, Result<PlanningResult> result);
};

Status PlannerService::Impl::append_durable(RecordType type,
                                            const std::vector<std::uint8_t>& payload) {
  if (store == nullptr) return Status::success();
  std::lock_guard<std::mutex> guard(durable_mutex);
  Status status = store->append(type, payload, nullptr);
  if (status.ok()) last_durable_sequence = store->last_sequence();
  return status;
}

PlanningResult PlannerService::Impl::run_plan(const PlanRequest& request) {
  // A request scoped to another coordinator epoch or boot incarnation is fenced
  // before anything is planned or persisted: one incarnation never acts under
  // another incarnation's authority.
  if (request.coordinator_epoch != epoch || request.boot != boot) {
    PlanningResult rejected;
    rejected.request = request.id;
    rejected.coordinator_epoch = request.coordinator_epoch;
    rejected.boot = request.boot;
    rejected.attempt = request.attempt;
    rejected.decision = PlanDecision::REJECTED_FENCED;
    rejected.request_digest = request.digest();
    Explanation explanation;
    explanation.code = ReasonCode::REQUEST_FENCED_BY_EPOCH;
    explanation.text =
        "request is scoped to coordinator epoch " +
        std::to_string(request.coordinator_epoch.value()) + " boot " +
        std::to_string(request.boot.value()) + " but this incarnation is epoch " +
        std::to_string(epoch.value()) + " boot " + std::to_string(boot.value());
    rejected.explanations.push_back(explanation);
    return rejected;
  }

  CanonicalWriter attempt_writer;
  attempt_writer.u64(request.id.value());
  attempt_writer.u64(request.attempt.value());
  attempt_writer.u64(request.coordinator_epoch.value());
  attempt_writer.u64(request.boot.value());
  const Digest request_digest = request.digest();
  attempt_writer.u64(request_digest.hi);
  attempt_writer.u64(request_digest.lo);
  const std::vector<std::uint8_t> attempt_payload = attempt_writer.take();

  if (store != nullptr && config.crash_point == CrashPoint::AFTER_ATTEMPT_APPEND_BEFORE_FLUSH) {
    // Bytes reach the journal without a flush and the process then dies: the
    // record may be absent, complete, or torn. Recovery must handle all three.
    std::lock_guard<std::mutex> guard(durable_mutex);
    (void)store->append(RecordType::ATTEMPT, attempt_payload, nullptr, false);
    crash_now(config.crash_point);
  }
  const Status appended = append_durable(RecordType::ATTEMPT, attempt_payload);
  if (!appended.ok()) {
    PlanningResult rejected;
    rejected.request = request.id;
    rejected.coordinator_epoch = request.coordinator_epoch;
    rejected.boot = request.boot;
    rejected.attempt = request.attempt;
    rejected.decision = PlanDecision::REJECTED_EXHAUSTED;
    Explanation explanation;
    explanation.code = ReasonCode::PERSISTENCE_INTEGRITY_FAILURE;
    explanation.text = appended.to_string();
    rejected.explanations.push_back(explanation);
    return rejected;
  }

  const PlanningResult result = planner->plan(request);

  std::vector<std::uint8_t> outcome_payload;
  RecordType outcome_type = RecordType::INFEASIBILITY;
  if (result.plan.has_value()) {
    outcome_type = RecordType::COMMITTED_PLAN;
    outcome_payload = encode_plan_record(*result.plan);
  } else {
    CanonicalWriter writer;
    writer.u64(result.request.value());
    writer.u8(static_cast<std::uint8_t>(result.decision));
    writer.u64(result.stats.nodes_expanded);
    writer.u64(result.stats.nodes_generated);
    writer.u64(result.request_digest.hi);
    writer.u64(result.request_digest.lo);
    outcome_payload = writer.take();
  }
  const Status committed = append_durable(outcome_type, outcome_payload);
  if (!committed.ok()) {
    PlanningResult rejected = result;
    rejected.decision = PlanDecision::REJECTED_EXHAUSTED;
    rejected.plan.reset();
    rejected.certificate.reset();
    Explanation explanation;
    explanation.code = ReasonCode::PERSISTENCE_INTEGRITY_FAILURE;
    explanation.text = committed.to_string();
    rejected.explanations.push_back(explanation);
    return rejected;
  }
  if (config.crash_point == CrashPoint::AFTER_COMMIT_BEFORE_PUBLISH) {
    // The outcome is durable but the caller never learns about it: reopening the
    // store shows a committed outcome whose acknowledgement was ambiguous.
    crash_now(config.crash_point);
  }
  return result;
}

ValidationReport PlannerService::Impl::run_validate(const PlanRequest& request,
                                                    const RecoveryPlan& plan) {
  const ValidationReport report = validate_plan(request, plan);
  if (store != nullptr) {
    CanonicalWriter writer;
    writer.u64(request.id.value());
    writer.u64(plan.plan_digest.hi);
    writer.u64(plan.plan_digest.lo);
    writer.boolean(report.valid);
    (void)append_durable(RecordType::EVIDENCE_LINEAGE, writer.buffer());
  }
  return report;
}

void PlannerService::Impl::complete(Job& job, Result<PlanningResult> result) {
  if (job.callback) {
    job.callback(result);  // delivered outside every internal lock
  }
  if (job.state) {
    {
      std::lock_guard<std::mutex> guard(job.state->mutex);
      if (result.ok()) {
        job.state->plan_result = result.value();
        job.state->status = Status::success();
      } else {
        job.state->status = result.status();
      }
      job.state->done = true;
    }
    job.state->cv.notify_all();
  }
}

void PlannerService::Impl::worker_loop() {
  for (;;) {
    Job job;
    {
      std::unique_lock<std::mutex> lock(queue_mutex);
      queue_cv.wait(lock, [this] { return stopping || !queue.empty(); });
      if (queue.empty()) {
        if (stopping) return;
        continue;
      }
      job = std::move(queue.front());
      queue.pop_front();
    }
    if (job.kind == Job::Kind::PLAN) {
      const PlanningResult result = run_plan(job.request);
      requests_completed.fetch_add(1);
      switch (result.decision) {
        case PlanDecision::PLAN_FOUND: plans_found.fetch_add(1); break;
        case PlanDecision::PROVEN_INFEASIBLE: plans_infeasible.fetch_add(1); break;
        case PlanDecision::INDETERMINATE_SEARCH_LIMIT:
        case PlanDecision::INDETERMINATE_INCOMPLETE_EVIDENCE:
          plans_indeterminate.fetch_add(1);
          break;
        default: requests_rejected.fetch_add(1); break;
      }
      complete(job, Result<PlanningResult>(result));
      if (config.crash_point == CrashPoint::AFTER_PUBLISH_BEFORE_ACK) {
        crash_now(config.crash_point);
      }
    } else {
      const ValidationReport report = run_validate(job.request, job.plan);
      validations_run.fetch_add(1);
      if (job.state) {
        {
          std::lock_guard<std::mutex> guard(job.state->mutex);
          job.state->validation_result = report;
          job.state->status = Status::success();
          job.state->done = true;
        }
        job.state->cv.notify_all();
      }
    }
  }
}

Result<std::shared_ptr<PlannerService>> PlannerService::start(const ServiceConfig& config,
                                                              const std::string& store_path) {
  std::shared_ptr<PlannerService> service(new PlannerService());
  service->impl_ = std::make_unique<Impl>();
  Impl& impl = *service->impl_;
  impl.config = config;
  impl.store_path = store_path;
  impl.planner = std::make_unique<Planner>(config.model_limits);
  impl.sessions = std::make_unique<SessionRegistry>(config.max_sessions ? config.max_sessions : 1);

  if (config.persist && !store_path.empty()) {
    OpenOptions options;
    options.limits = config.store_limits;
    options.model_limits = config.model_limits;
    Result<std::unique_ptr<DurableStore>> opened = DurableStore::open(store_path, options);
    if (!opened.ok()) return opened.status();
    impl.recovery = opened.value()->recovery();
    impl.epoch = opened.value()->epoch();
    impl.boot = opened.value()->boot();
    impl.last_durable_sequence = opened.value()->last_sequence();
    impl.store = std::move(opened.value());
    service->store_ = impl.store.get();
  } else {
    impl.epoch = Epoch::from_value(1);
    impl.boot = BootId::from_value(1);
  }

  const std::uint32_t threads = config.worker_threads == 0 ? 1 : config.worker_threads;
  impl.workers.reserve(threads);
  for (std::uint32_t index = 0; index < threads; ++index) {
    impl.workers.emplace_back([&impl] { impl.worker_loop(); });
  }
  return service;
}

PlannerService::~PlannerService() {
  if (impl_) {
    (void)shutdown();
  }
}

Result<PlanningResult> PlannerService::plan(const PlanRequest& request) {
  Impl& impl = *impl_;
  std::shared_ptr<JobState> state = std::make_shared<JobState>();
  {
    std::lock_guard<std::mutex> guard(impl.queue_mutex);
    if (impl.stopping) return Status::error(StatusCode::CLOSED, "service is shutting down");
    if (impl.queue.size() >= impl.config.max_queue_depth) {
      impl.requests_refused_exhausted.fetch_add(1);
      return Status::error(StatusCode::EXHAUSTED, "work queue is full");
    }
    Impl::Job job;
    job.kind = Impl::Job::Kind::PLAN;
    job.request = request;
    job.state = state;
    impl.queue.push_back(std::move(job));
    impl.requests_accepted.fetch_add(1);
    if (impl.queue.size() > impl.queue_high_water) {
      impl.queue_high_water = impl.queue.size();
    }
  }
  impl.queue_cv.notify_one();

  std::unique_lock<std::mutex> lock(state->mutex);
  state->cv.wait(lock, [&state] { return state->done; });
  if (!state->status.ok()) return state->status;
  return state->plan_result;
}

Result<ValidationReport> PlannerService::validate(const PlanRequest& request,
                                                  const RecoveryPlan& plan) {
  Impl& impl = *impl_;
  std::shared_ptr<JobState> state = std::make_shared<JobState>();
  {
    std::lock_guard<std::mutex> guard(impl.queue_mutex);
    if (impl.stopping) return Status::error(StatusCode::CLOSED, "service is shutting down");
    if (impl.queue.size() >= impl.config.max_queue_depth) {
      impl.requests_refused_exhausted.fetch_add(1);
      return Status::error(StatusCode::EXHAUSTED, "work queue is full");
    }
    Impl::Job job;
    job.kind = Impl::Job::Kind::VALIDATE;
    job.request = request;
    job.plan = plan;
    job.state = state;
    impl.queue.push_back(std::move(job));
    impl.requests_accepted.fetch_add(1);
  }
  impl.queue_cv.notify_one();

  std::unique_lock<std::mutex> lock(state->mutex);
  state->cv.wait(lock, [&state] { return state->done; });
  if (!state->status.ok()) return state->status;
  return state->validation_result;
}

Status PlannerService::submit_plan(const PlanRequest& request,
                                   std::function<void(Result<PlanningResult>)> callback) {
  Impl& impl = *impl_;
  std::lock_guard<std::mutex> guard(impl.queue_mutex);
  if (impl.stopping) return Status::error(StatusCode::CLOSED, "service is shutting down");
  if (impl.queue.size() >= impl.config.max_queue_depth) {
    impl.requests_refused_exhausted.fetch_add(1);
    return Status::error(StatusCode::EXHAUSTED, "work queue is full");
  }
  Impl::Job job;
  job.kind = Impl::Job::Kind::PLAN;
  job.request = request;
  job.callback = std::move(callback);
  impl.queue.push_back(std::move(job));
  impl.requests_accepted.fetch_add(1);
  if (impl.queue.size() > impl.queue_high_water) {
    impl.queue_high_water = impl.queue.size();
  }
  impl.queue_cv.notify_one();
  return Status::success();
}

Status PlannerService::shutdown() {
  Impl& impl = *impl_;
  std::deque<Impl::Job> pending;
  {
    std::lock_guard<std::mutex> guard(impl.queue_mutex);
    impl.stopping = true;
    pending.swap(impl.queue);
  }
  impl.queue_cv.notify_all();
  // Queued work is completed explicitly with a CLOSED status; nothing is
  // dropped silently and no waiter can block forever.
  for (Impl::Job& job : pending) {
    if (job.callback) {
      job.callback(Result<PlanningResult>(
          Status::error(StatusCode::CLOSED, "service shut down before the job ran")));
    }
    if (job.state) {
      {
        std::lock_guard<std::mutex> guard(job.state->mutex);
        job.state->status = Status::error(StatusCode::CLOSED,
                                          "service shut down before the job ran");
        job.state->done = true;
      }
      job.state->cv.notify_all();
    }
  }
  for (std::thread& worker : impl.workers) {
    if (worker.joinable()) worker.join();  // joined without holding any lock
  }
  impl.workers.clear();
  if (impl.store) {
    std::lock_guard<std::mutex> guard(impl.durable_mutex);
    (void)impl.store->commit_snapshot();
    impl.store.reset();
    store_ = nullptr;
  }
  return Status::success();
}

ServiceStats PlannerService::stats() const {
  const Impl& impl = *impl_;
  ServiceStats stats;
  stats.requests_accepted = impl.requests_accepted.load();
  stats.requests_completed = impl.requests_completed.load();
  stats.requests_rejected = impl.requests_rejected.load();
  stats.requests_refused_exhausted = impl.requests_refused_exhausted.load();
  stats.plans_found = impl.plans_found.load();
  stats.plans_infeasible = impl.plans_infeasible.load();
  stats.plans_indeterminate = impl.plans_indeterminate.load();
  stats.validations_run = impl.validations_run.load();
  stats.queue_high_water = impl.queue_high_water.load();
  stats.thread_count = impl.workers.size();
  return stats;
}

Epoch PlannerService::epoch() const { return impl_->epoch; }
BootId PlannerService::boot() const { return impl_->boot; }
Sequence PlannerService::last_durable_sequence() const { return impl_->last_durable_sequence; }
const RecoveryReport& PlannerService::recovery() const { return impl_->recovery; }

}  // namespace nrp
