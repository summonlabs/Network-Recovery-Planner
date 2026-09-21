// Network Recovery Planner - real multiprocess, crash and restart proof.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include "nrp/persistence.hpp"
#include "nrp/planner.hpp"
#include "nrp/runtime.hpp"
#include "nrp/validate.hpp"
#include "support/fixture.hpp"
#include "support/process_helper.hpp"
#include "support/test_support.hpp"

using namespace nrp;
using namespace nrp::test;

namespace {

std::string scratch_directory(const char* name) {
  const std::filesystem::path directory =
      std::filesystem::temp_directory_path() / (std::string("nrp_mp_") + name);
  std::error_code ec;
  std::filesystem::remove_all(directory, ec);
  std::filesystem::create_directories(directory, ec);
  return directory.string();
}

void cleanup_directory(const std::string& path) {
  std::error_code ec;
  std::filesystem::remove_all(path, ec);
}

PlanRequest request_for(Epoch epoch, BootId boot) {
  TeachingFabric fabric;
  fabric.builder.set_epoch(epoch);
  fabric.builder.set_boot(boot);
  return fabric.request();
}

struct ServerHandle {
  ChildProcess process;
  std::string port_file;
  std::uint16_t port = 0;
  Epoch epoch;
  BootId boot;
};

bool launch_server(ServerHandle* handle,
                   const std::string& directory,
                   const std::string& store,
                   const std::string& crash_point) {
  handle->port_file = directory + "/port.txt";
  std::error_code ec;
  std::filesystem::remove(handle->port_file, ec);
  std::vector<std::string> arguments{"--port", "0", "--store", store, "--port-file",
                                     handle->port_file, "--run-forever", "--workers", "2"};
  if (!crash_point.empty()) {
    arguments.push_back("--crash-point");
    arguments.push_back(crash_point);
  }
  if (!handle->process.start(NRP_SERVER_EXE, arguments)) return false;
  std::string content;
  if (!wait_for_file(handle->port_file, "", 600, 25, &content)) return false;
  unsigned long port = 0;
  unsigned long long epoch = 0;
  unsigned long long boot = 0;
  if (std::sscanf(content.c_str(), "%lu %llu %llu", &port, &epoch, &boot) != 3) return false;
  handle->port = static_cast<std::uint16_t>(port);
  handle->epoch = Epoch::from_value(epoch);
  handle->boot = BootId::from_value(boot);
  return true;
}

std::size_t count_records(const std::string& store, RecordType type) {
  const Result<std::unique_ptr<DurableStore>> opened = DurableStore::open(store, OpenOptions{});
  if (!opened.ok()) return 0;
  std::size_t count = 0;
  for (const DurableRecord& record : opened.value()->records()) {
    if (record.type == type) ++count;
  }
  return count;
}

}  // namespace

NRP_TEST(multiprocess, server_serves_plans_then_restarts_conservatively) {
  const std::string directory = scratch_directory("lifecycle");
  const std::string store = directory + "/store.bin";
  ServerHandle server;
  NRP_REQUIRE(launch_server(&server, directory, store, ""));

  {
    ClientConfig config;
    config.port = server.port;
    const Result<std::unique_ptr<PlanningClient>> client = PlanningClient::connect(config);
    NRP_REQUIRE(client.ok());
    const PlanRequest request = request_for(server.epoch, server.boot);
    const Result<PlanningResult> result = client.value()->plan(request);
    NRP_REQUIRE(result.ok());
    NRP_CHECK(result.value().decision == PlanDecision::PLAN_FOUND);
    NRP_REQUIRE(result.value().plan.has_value());
    NRP_CHECK(validate_plan(request, *result.value().plan).valid);
    const Result<ValidationReport> report =
        client.value()->validate(request, *result.value().plan);
    NRP_REQUIRE(report.ok());
    NRP_CHECK(report.value().valid);
    NRP_CHECK(client.value()->ping().ok());
    (void)client.value()->close();
  }

  NRP_CHECK(server.process.kill_hard());
  const int exit_code = server.process.wait();
  NRP_CHECK(exit_code == 70);
  NRP_CHECK_EQ(count_records(store, RecordType::COMMITTED_PLAN), static_cast<std::size_t>(1));

  Epoch durable_epoch;
  {
    const Result<std::unique_ptr<DurableStore>> opened = DurableStore::open(store, OpenOptions{});
    NRP_REQUIRE(opened.ok());
    durable_epoch = opened.value()->epoch();
  }
  NRP_CHECK(durable_epoch > server.epoch);

  ServerHandle restarted;
  NRP_REQUIRE(launch_server(&restarted, directory, store, ""));
  NRP_CHECK(restarted.epoch > server.epoch);
  NRP_CHECK(restarted.boot > server.boot);

  {
    ClientConfig config;
    config.port = restarted.port;
    const Result<std::unique_ptr<PlanningClient>> client = PlanningClient::connect(config);
    NRP_REQUIRE(client.ok());
    const PlanRequest fresh = request_for(restarted.epoch, restarted.boot);
    const Result<PlanningResult> result = client.value()->plan(fresh);
    NRP_REQUIRE(result.ok());
    NRP_CHECK(result.value().decision == PlanDecision::PLAN_FOUND);

    // A request built for the pre-restart incarnation must be refused.
    const PlanRequest stale = request_for(server.epoch, server.boot);
    const Result<PlanningResult> refused = client.value()->plan(stale);
    NRP_REQUIRE(refused.ok());
    NRP_CHECK(refused.value().decision != PlanDecision::PLAN_FOUND);
    NRP_CHECK(is_rejection(refused.value().decision) ||
              refused.value().decision == PlanDecision::INDETERMINATE_INCOMPLETE_EVIDENCE);
    (void)client.value()->close();
  }

  NRP_CHECK(restarted.process.kill_hard());
  (void)restarted.process.wait();
  cleanup_directory(directory);
}

NRP_TEST(multiprocess, crash_after_commit_before_publish_is_conservative) {
  const std::string directory = scratch_directory("commit");
  const std::string store = directory + "/store.bin";
  ServerHandle server;
  NRP_REQUIRE(launch_server(&server, directory, store, "AFTER_COMMIT_BEFORE_PUBLISH"));

  {
    ClientConfig config;
    config.port = server.port;
    const Result<std::unique_ptr<PlanningClient>> client = PlanningClient::connect(config);
    NRP_REQUIRE(client.ok());
    const PlanRequest request = request_for(server.epoch, server.boot);
    const Result<PlanningResult> result = client.value()->plan(request);
    // The acknowledgement is deliberately lost: the client must observe a
    // failure, never a fabricated success.
    NRP_CHECK(!result.ok());
    (void)client.value()->close();
  }
  const int exit_code = server.process.wait();
  NRP_CHECK(exit_code == 70);

  // The outcome is nonetheless durable, and reopening advances the incarnation.
  {
    const Result<std::unique_ptr<DurableStore>> opened = DurableStore::open(store, OpenOptions{});
    NRP_REQUIRE(opened.ok());
    NRP_CHECK(opened.value()->epoch() > server.epoch);
    std::size_t attempts = 0;
    std::size_t committed = 0;
    for (const DurableRecord& record : opened.value()->records()) {
      if (record.type == RecordType::ATTEMPT) ++attempts;
      if (record.type == RecordType::COMMITTED_PLAN) ++committed;
    }
    NRP_CHECK_EQ(attempts, static_cast<std::size_t>(1));
    NRP_CHECK_EQ(committed, static_cast<std::size_t>(1));
    NRP_CHECK(opened.value()->recovery().fenced_dynamic_records >= 1);
  }
  cleanup_directory(directory);
}

NRP_TEST(multiprocess, crash_before_flush_recovers_a_partial_journal) {
  const std::string directory = scratch_directory("flush");
  const std::string store = directory + "/store.bin";
  ServerHandle server;
  NRP_REQUIRE(launch_server(&server, directory, store, "AFTER_ATTEMPT_APPEND_BEFORE_FLUSH"));
  {
    ClientConfig config;
    config.port = server.port;
    const Result<std::unique_ptr<PlanningClient>> client = PlanningClient::connect(config);
    NRP_REQUIRE(client.ok());
    const Result<PlanningResult> result =
        client.value()->plan(request_for(server.epoch, server.boot));
    NRP_CHECK(!result.ok());
    (void)client.value()->close();
  }
  NRP_CHECK_EQ(server.process.wait(), 70);
  // The attempt may be absent, complete, or torn; reopening must succeed in all
  // three cases and must never restore the attempt as live state.
  const Result<std::unique_ptr<DurableStore>> opened = DurableStore::open(store, OpenOptions{});
  NRP_CHECK_MSG(opened.ok(),
                "reopen failed: " << (opened.ok() ? std::string() : opened.status().to_string()));
  cleanup_directory(directory);
}

NRP_TEST(multiprocess, crash_after_publish_leaves_a_valid_durable_outcome) {
  const std::string directory = scratch_directory("publish");
  const std::string store = directory + "/store.bin";
  ServerHandle server;
  NRP_REQUIRE(launch_server(&server, directory, store, "AFTER_PUBLISH_BEFORE_ACK"));
  bool client_saw_a_plan = false;
  {
    ClientConfig config;
    config.port = server.port;
    const Result<std::unique_ptr<PlanningClient>> client = PlanningClient::connect(config);
    NRP_REQUIRE(client.ok());
    const PlanRequest request = request_for(server.epoch, server.boot);
    const Result<PlanningResult> result = client.value()->plan(request);
    if (result.ok() && result.value().plan.has_value()) {
      client_saw_a_plan = true;
      NRP_CHECK(validate_plan(request, *result.value().plan).valid);
    }
    (void)client.value()->close();
  }
  NRP_CHECK_EQ(server.process.wait(), 70);
  NRP_CHECK_EQ(count_records(store, RecordType::COMMITTED_PLAN), static_cast<std::size_t>(1));
  (void)client_saw_a_plan;  // either observation is conservative
  cleanup_directory(directory);
}

NRP_TEST(multiprocess, hostile_frames_are_rejected_and_the_server_survives) {
  const std::string directory = scratch_directory("hostile");
  const std::string store = directory + "/store.bin";
  ServerHandle server;
  NRP_REQUIRE(launch_server(&server, directory, store, ""));

  {
    ClientConfig config;
    config.port = server.port;
    const Result<std::unique_ptr<PlanningClient>> client = PlanningClient::connect(config);
    NRP_REQUIRE(client.ok());
    // A frame carrying another session identity.
    const std::vector<std::uint8_t> wrong_session =
        encode_frame(FrameType::PLAN_REQUEST, 999999, server.epoch, server.boot, Sequence{2}, {1});
    NRP_CHECK(client.value()->send_raw_bytes(wrong_session).ok());
    const Result<std::vector<std::uint8_t>> answer = client.value()->read_raw_frame({});
    NRP_REQUIRE(answer.ok());
    Frame frame;
    std::size_t consumed = 0;
    NRP_REQUIRE(decode_frame(answer.value().data(), answer.value().size(), {}, &frame, &consumed).ok());
    NRP_CHECK_EQ(static_cast<int>(frame.header.type), static_cast<int>(FrameType::ERROR_FRAME));
    (void)client.value()->close();
  }
  {
    // A frame with a corrupted payload checksum.
    ClientConfig config;
    config.port = server.port;
    const Result<std::unique_ptr<PlanningClient>> client = PlanningClient::connect(config);
    NRP_REQUIRE(client.ok());
    std::vector<std::uint8_t> frame =
        encode_frame(FrameType::PLAN_REQUEST, client.value()->session().value(),
                     client.value()->epoch(), client.value()->boot(), Sequence{2}, {1, 2, 3});
    frame[kFrameHeaderSize] ^= 0xFF;
    NRP_CHECK(client.value()->send_raw_bytes(frame).ok());
    const Result<std::vector<std::uint8_t>> answer = client.value()->read_raw_frame({});
    NRP_REQUIRE(answer.ok());
    Frame decoded;
    std::size_t consumed = 0;
    NRP_CHECK(decode_frame(answer.value().data(), answer.value().size(), {}, &decoded, &consumed)
                  .ok());
    NRP_CHECK_EQ(static_cast<int>(decoded.header.type), static_cast<int>(FrameType::ERROR_FRAME));
    (void)client.value()->close();
  }
  {
    // A complete frame of garbage: the magic is wrong, so the frame is refused
    // and the connection is dropped after the error is reported.
    ClientConfig config;
    config.port = server.port;
    const Result<std::unique_ptr<PlanningClient>> client = PlanningClient::connect(config);
    NRP_REQUIRE(client.ok());
    std::vector<std::uint8_t> garbage(kFrameHeaderSize, 0xAB);
    NRP_CHECK(client.value()->send_raw_bytes(garbage).ok());
    const Result<std::vector<std::uint8_t>> answer = client.value()->read_raw_frame({});
    NRP_REQUIRE(answer.ok());
    Frame decoded;
    std::size_t consumed = 0;
    NRP_CHECK(decode_frame(answer.value().data(), answer.value().size(), {}, &decoded, &consumed)
                  .ok());
    NRP_CHECK_EQ(static_cast<int>(decoded.header.type), static_cast<int>(FrameType::ERROR_FRAME));
    (void)client.value()->close();
  }
  {
    // The first frame of a connection must be HELLO.
    ClientConfig config;
    config.port = server.port;
    const Result<std::unique_ptr<PlanningClient>> client = PlanningClient::connect(config);
    NRP_REQUIRE(client.ok());
    const std::vector<std::uint8_t> status =
        encode_frame(FrameType::STATUS_REQUEST, 0, server.epoch, server.boot, Sequence{1}, {});
    NRP_CHECK(client.value()->send_raw_bytes(status).ok());
    const Result<std::vector<std::uint8_t>> answer = client.value()->read_raw_frame({});
    NRP_REQUIRE(answer.ok());
    Frame decoded;
    std::size_t consumed = 0;
    NRP_CHECK(decode_frame(answer.value().data(), answer.value().size(), {}, &decoded, &consumed)
                  .ok());
    NRP_CHECK_EQ(static_cast<int>(decoded.header.type), static_cast<int>(FrameType::ERROR_FRAME));
    (void)client.value()->close();
  }
  {
    // A truncated prefix produces no reply: the server waits for the remainder of
    // the frame, so the test closes the connection instead of waiting. That read
    // is released by the close, and the server stays available for other clients.
    ClientConfig config;
    config.port = server.port;
    const Result<std::unique_ptr<PlanningClient>> client = PlanningClient::connect(config);
    NRP_REQUIRE(client.ok());
    const std::vector<std::uint8_t> partial{0x4E, 0x52, 0x50, 0x46};
    NRP_CHECK(client.value()->send_raw_bytes(partial).ok());
    (void)client.value()->close();
  }
  {
    // The server is still healthy.
    ClientConfig config;
    config.port = server.port;
    const Result<std::unique_ptr<PlanningClient>> client = PlanningClient::connect(config);
    NRP_REQUIRE(client.ok());
    NRP_CHECK(client.value()->ping().ok());
    const Result<PlanningResult> result =
        client.value()->plan(request_for(server.epoch, server.boot));
    NRP_REQUIRE(result.ok());
    NRP_CHECK(result.value().decision == PlanDecision::PLAN_FOUND);
    (void)client.value()->close();
  }

  NRP_CHECK(server.process.kill_hard());
  (void)server.process.wait();
  cleanup_directory(directory);
}

NRP_TEST(multiprocess, graceful_shutdown_releases_clients_and_exits) {
  const std::string directory = scratch_directory("shutdown");
  const std::string store = directory + "/store.bin";
  const std::string port_file = directory + "/port.txt";
  ChildProcess server;
  NRP_REQUIRE(server.start(NRP_SERVER_EXE,
                           {"--port", "0", "--store", store, "--port-file", port_file, "--workers",
                            "2"},
                           true));
  std::string content;
  NRP_REQUIRE(wait_for_file(port_file, "", 600, 25, &content));
  unsigned long port = 0;
  unsigned long long epoch = 0;
  unsigned long long boot = 0;
  NRP_REQUIRE(std::sscanf(content.c_str(), "%lu %llu %llu", &port, &epoch, &boot) == 3);

  ClientConfig config;
  config.port = static_cast<std::uint16_t>(port);
  const Result<std::unique_ptr<PlanningClient>> client = PlanningClient::connect(config);
  NRP_REQUIRE(client.ok());
  NRP_CHECK(client.value()->ping().ok());

  // A client blocked in a read must be released when the server shuts down.
  bool released = false;
  Status blocked_status = Status::error(StatusCode::CLOSED, "not run");
  std::thread blocked([&] {
    blocked_status = client.value()->ping();
    released = true;
  });
  server.close_stdin();
  const int exit_code = server.wait();
  blocked.join();
  NRP_CHECK_EQ(exit_code, 0);
  NRP_CHECK(released);
  NRP_CHECK_MSG(!blocked_status.ok(), "a blocked read must be released, not served");
  (void)client.value()->close();
  cleanup_directory(directory);
}
