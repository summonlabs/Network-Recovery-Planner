// Network Recovery Planner - concurrency and lifecycle tests.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Every rendezvous here is a deterministic latch or barrier; no test depends on
// sleeping in the hope that another thread has made progress.
#include <atomic>
#include <barrier>
#include <latch>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "nrp/runtime.hpp"
#include "support/fixture.hpp"
#include "support/test_support.hpp"

using namespace nrp;
using namespace nrp::test;

namespace {

PlanRequest request_for(Epoch epoch, BootId boot, std::uint64_t case_index) {
  TeachingFabric fabric;
  fabric.builder.set_epoch(epoch);
  fabric.builder.set_boot(boot);
  return fabric.builder.build(RequestId::from_value(1 + case_index),
                              AttemptId::from_value(1 + case_index), fixture_policy());
}

}  // namespace

NRP_TEST(concurrency, session_registry_enforces_authority_and_bounds) {
  SessionRegistry registry(2);
  const Result<SessionRecord> first =
      registry.create(Epoch::from_value(1), BootId::from_value(1), 11);
  NRP_REQUIRE(first.ok());
  NRP_CHECK_EQ(registry.size(), 1u);
  NRP_CHECK(registry.accept(first.value().id, Epoch::from_value(1), BootId::from_value(1),
                            Sequence{1})
                .ok());
  // Replay and regression are refused.
  NRP_CHECK(!registry.accept(first.value().id, Epoch::from_value(1), BootId::from_value(1),
                             Sequence{1})
                 .ok());
  NRP_CHECK(!registry.accept(first.value().id, Epoch::from_value(1), BootId::from_value(1),
                             Sequence{0})
                 .ok());
  // A different incarnation is refused.
  NRP_CHECK(!registry.accept(first.value().id, Epoch::from_value(2), BootId::from_value(1),
                             Sequence{2})
                 .ok());
  NRP_CHECK(!registry.accept(first.value().id, Epoch::from_value(1), BootId::from_value(2),
                             Sequence{2})
                 .ok());
  // Unknown sessions are refused.
  NRP_CHECK(!registry.accept(SessionId::from_value(999), Epoch::from_value(1),
                             BootId::from_value(1), Sequence{1})
                 .ok());
  const Result<SessionRecord> second =
      registry.create(Epoch::from_value(1), BootId::from_value(1), 12);
  NRP_REQUIRE(second.ok());
  const Result<SessionRecord> third =
      registry.create(Epoch::from_value(1), BootId::from_value(1), 13);
  NRP_CHECK(!third.ok());
  NRP_CHECK_EQ(static_cast<int>(third.status().code()), static_cast<int>(StatusCode::EXHAUSTED));
  NRP_CHECK(registry.release(first.value().id).ok());
  const Result<SessionRecord> recycled =
      registry.create(Epoch::from_value(1), BootId::from_value(1), 14);
  NRP_CHECK(recycled.ok());
  NRP_CHECK(registry.high_water() >= 2u);
}

NRP_TEST(concurrency, concurrent_sessions_never_cross_identities) {
  SessionRegistry registry(64);
  constexpr int kThreads = 8;
  std::barrier start(kThreads);
  std::vector<SessionId> sessions(static_cast<std::size_t>(kThreads));
  std::vector<std::thread> threads;
  for (int index = 0; index < kThreads; ++index) {
    threads.emplace_back([&registry, &start, &sessions, index] {
      start.arrive_and_wait();
      const Result<SessionRecord> record =
          registry.create(Epoch::from_value(1), BootId::from_value(1),
                          static_cast<std::uint64_t>(100 + index));
      if (record.ok()) sessions[static_cast<std::size_t>(index)] = record.value().id;
    });
  }
  for (std::thread& thread : threads) thread.join();
  for (int index = 0; index < kThreads; ++index) {
    NRP_CHECK(!sessions[static_cast<std::size_t>(index)].is_zero());
  }
  std::sort(sessions.begin(), sessions.end());
  NRP_CHECK(std::adjacent_find(sessions.begin(), sessions.end()) == sessions.end());
  NRP_CHECK_EQ(registry.size(), static_cast<std::uint32_t>(kThreads));
}

NRP_TEST(concurrency, service_plans_concurrently_and_stays_deterministic) {
  ServiceConfig config;
  config.worker_threads = 4;
  config.persist = false;
  const Result<std::shared_ptr<PlannerService>> service = PlannerService::start(config, "");
  NRP_REQUIRE(service.ok());

  constexpr int kThreads = 8;
  constexpr int kPerThread = 12;
  std::barrier start(kThreads);
  std::atomic<int> planned{0};
  std::atomic<int> mismatched{0};
  // Determinism is checked per request identity: every thread planning the same
  // request must produce the same plan digest.
  std::map<std::uint64_t, Digest> reference_digests;
  std::mutex digest_mutex;
  std::vector<std::thread> threads;
  for (int index = 0; index < kThreads; ++index) {
    threads.emplace_back([&, index] {
      start.arrive_and_wait();
      for (int iteration = 0; iteration < kPerThread; ++iteration) {
        const PlanRequest request =
            request_for(service.value()->epoch(), service.value()->boot(),
                        static_cast<std::uint64_t>(iteration));
        const Result<PlanningResult> result = service.value()->plan(request);
        if (!result.ok() || !result.value().plan.has_value()) {
          ++mismatched;
          continue;
        }
        ++planned;
        std::lock_guard<std::mutex> guard(digest_mutex);
        const std::uint64_t key = static_cast<std::uint64_t>(iteration);
        const auto found = reference_digests.find(key);
        if (found == reference_digests.end()) {
          reference_digests.emplace(key, result.value().plan->plan_digest);
        } else if (found->second != result.value().plan->plan_digest) {
          ++mismatched;
        }
      }
    });
  }
  for (std::thread& thread : threads) thread.join();
  NRP_CHECK_EQ(mismatched.load(), 0);
  NRP_CHECK_EQ(planned.load(), kThreads * kPerThread);
  const ServiceStats stats = service.value()->stats();
  NRP_CHECK_EQ(stats.plans_found, static_cast<std::uint64_t>(kThreads * kPerThread));
  NRP_CHECK(service.value()->shutdown().ok());
  NRP_CHECK(service.value()->shutdown().ok());  // idempotent
}

NRP_TEST(concurrency, shutdown_completes_every_queued_job) {
  ServiceConfig config;
  config.worker_threads = 2;
  config.persist = false;
  const Result<std::shared_ptr<PlannerService>> service = PlannerService::start(config, "");
  NRP_REQUIRE(service.ok());

  constexpr int kJobs = 32;
  std::atomic<int> callbacks{0};
  std::vector<PlanRequest> requests;
  requests.reserve(kJobs);
  for (int index = 0; index < kJobs; ++index) {
    requests.push_back(request_for(service.value()->epoch(), service.value()->boot(),
                                   static_cast<std::uint64_t>(index)));
  }
  int accepted = 0;
  for (int index = 0; index < kJobs; ++index) {
    const Status status = service.value()->submit_plan(
        requests[static_cast<std::size_t>(index)],
        [&callbacks](Result<PlanningResult>) { callbacks.fetch_add(1); });
    if (status.ok()) ++accepted;
  }
  NRP_CHECK(service.value()->shutdown().ok());
  NRP_CHECK_EQ(callbacks.load(), accepted);

  // After shutdown, work is refused explicitly instead of hanging.
  const Result<PlanningResult> refused = service.value()->plan(requests[0]);
  NRP_CHECK(!refused.ok());
  NRP_CHECK_EQ(static_cast<int>(refused.status().code()), static_cast<int>(StatusCode::CLOSED));
}

NRP_TEST(concurrency, requests_from_another_incarnation_are_fenced) {
  ServiceConfig config;
  config.worker_threads = 1;
  config.persist = false;
  const Result<std::shared_ptr<PlannerService>> service = PlannerService::start(config, "");
  NRP_REQUIRE(service.ok());
  const Epoch epoch = service.value()->epoch();
  const BootId boot = service.value()->boot();

  const PlanRequest stale = request_for(Epoch::from_value(epoch.value() + 1), boot, 1);
  const Result<PlanningResult> refused = service.value()->plan(stale);
  NRP_REQUIRE(refused.ok());
  NRP_CHECK(refused.value().decision == PlanDecision::REJECTED_FENCED);
  NRP_CHECK(!refused.value().plan.has_value());

  const PlanRequest other_boot = request_for(epoch, BootId::from_value(boot.value() + 3), 2);
  const Result<PlanningResult> refused_boot = service.value()->plan(other_boot);
  NRP_REQUIRE(refused_boot.ok());
  NRP_CHECK(refused_boot.value().decision == PlanDecision::REJECTED_FENCED);

  const PlanRequest current = request_for(epoch, boot, 3);
  const Result<PlanningResult> accepted = service.value()->plan(current);
  NRP_REQUIRE(accepted.ok());
  NRP_CHECK(accepted.value().decision == PlanDecision::PLAN_FOUND);
  NRP_CHECK(service.value()->shutdown().ok());
}

NRP_TEST(concurrency, queue_bounds_refuse_deterministically) {
  ServiceConfig config;
  config.worker_threads = 1;
  config.persist = false;
  config.max_queue_depth = 0;
  const Result<std::shared_ptr<PlannerService>> service = PlannerService::start(config, "");
  NRP_REQUIRE(service.ok());
  const Result<PlanningResult> refused =
      service.value()->plan(request_for(service.value()->epoch(), service.value()->boot(), 1));
  NRP_CHECK(!refused.ok());
  NRP_CHECK_EQ(static_cast<int>(refused.status().code()), static_cast<int>(StatusCode::EXHAUSTED));
  NRP_CHECK_EQ(service.value()->stats().requests_refused_exhausted, 1ull);
  NRP_CHECK(service.value()->shutdown().ok());
}

NRP_TEST(concurrency, in_process_server_serves_clients_and_stops_cleanly) {
  ServiceConfig config;
  config.worker_threads = 2;
  config.persist = false;
  const Result<std::shared_ptr<PlannerService>> service = PlannerService::start(config, "");
  NRP_REQUIRE(service.ok());
  ServerConfig server_config;
  server_config.port = 0;
  const Result<std::unique_ptr<PlanningServer>> server =
      PlanningServer::start(service.value(), server_config);
  NRP_REQUIRE(server.ok());
  NRP_CHECK(server.value()->port() != 0);

  constexpr int kClients = 4;
  constexpr int kRequests = 5;
  std::barrier start(kClients);
  std::atomic<int> failures{0};
  std::vector<std::thread> threads;
  for (int index = 0; index < kClients; ++index) {
    threads.emplace_back([&, index] {
      ClientConfig client_config;
      client_config.port = server.value()->port();
      const Result<std::unique_ptr<PlanningClient>> client = PlanningClient::connect(client_config);
      if (!client.ok()) {
        ++failures;
        return;
      }
      start.arrive_and_wait();
      for (int iteration = 0; iteration < kRequests; ++iteration) {
        const Result<PlanningResult> result = client.value()->plan(
            request_for(client.value()->epoch(), client.value()->boot(),
                        static_cast<std::uint64_t>(index * kRequests + iteration)));
        if (!result.ok() || result.value().decision != PlanDecision::PLAN_FOUND) {
          ++failures;
        }
      }
      (void)client.value()->close();
    });
  }
  for (std::thread& thread : threads) thread.join();
  NRP_CHECK_EQ(failures.load(), 0);
  NRP_CHECK(server.value()->stats().connections_accepted >= kClients);

  // A blocked reader is released by shutdown rather than left hanging.
  ClientConfig client_config;
  client_config.port = server.value()->port();
  const Result<std::unique_ptr<PlanningClient>> blocked = PlanningClient::connect(client_config);
  NRP_REQUIRE(blocked.ok());
  std::atomic<bool> released{false};
  Result<PlanningResult> blocked_result(Status::error(StatusCode::CLOSED, "not run"));
  std::thread reader([&] {
    blocked_result = blocked.value()->plan(request_for(blocked.value()->epoch(),
                                                       blocked.value()->boot(), 99));
    released = true;
  });
  NRP_CHECK(server.value()->shutdown().ok());
  reader.join();
  NRP_CHECK(released.load());
  NRP_CHECK(!blocked_result.ok());
  (void)blocked.value()->close();
  NRP_CHECK(server.value()->shutdown().ok());  // idempotent
  NRP_CHECK(service.value()->shutdown().ok());
}

NRP_TEST(concurrency, socket_move_and_close_semantics) {
  transport::Socket invalid;
  NRP_CHECK(!invalid.valid());
  NRP_CHECK(!invalid.send_all(nullptr, 0).ok());
  invalid.close();  // closing an invalid socket is a no-op, never a double close

  const Result<transport::Socket> socket = transport::Socket::connect("127.0.0.1", 1);
  NRP_CHECK(!socket.ok());  // nothing listens on port 1
}
