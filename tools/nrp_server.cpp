// Network Recovery Planner - framed protocol server executable.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <thread>

#include "nrp/runtime.hpp"
#include "nrp/version.hpp"

namespace {

const char* kUsage =
    "nrp-server [options]\n"
    "  --port N            listen port (0 selects an ephemeral port)\n"
    "  --bind ADDRESS      bind address (default 127.0.0.1)\n"
    "  --store PATH        durable store path (persistence is disabled without it)\n"
    "  --workers N         worker threads (default 4)\n"
    "  --port-file PATH    write the bound port, epoch and boot identity to PATH\n"
    "  --crash-point NAME  fault injection boundary (documented in the README)\n"
    "  --run-forever       do not exit when stdin closes\n"
    "  --max-sessions N    session table bound\n";

std::string argument(int argc, char** argv, const char* flag, const char* fallback) {
  for (int index = 1; index + 1 < argc; ++index) {
    if (std::strcmp(argv[index], flag) == 0) return argv[index + 1];
  }
  return fallback;
}

bool has_flag(int argc, char** argv, const char* flag) {
  for (int index = 1; index < argc; ++index) {
    if (std::strcmp(argv[index], flag) == 0) return true;
  }
  return false;
}

}  // namespace

int main(int argc, char** argv) {
  using namespace nrp;
  if (has_flag(argc, argv, "--help")) {
    std::fputs(kUsage, stdout);
    return 0;
  }
  const std::uint16_t port =
      static_cast<std::uint16_t>(std::strtoul(argument(argc, argv, "--port", "0").c_str(), nullptr, 10));
  const std::string bind_address = argument(argc, argv, "--bind", "127.0.0.1");
  const std::string store_path = argument(argc, argv, "--store", "");
  const std::uint32_t workers = static_cast<std::uint32_t>(
      std::strtoul(argument(argc, argv, "--workers", "4").c_str(), nullptr, 10));
  const std::uint32_t max_sessions = static_cast<std::uint32_t>(
      std::strtoul(argument(argc, argv, "--max-sessions", "64").c_str(), nullptr, 10));
  const std::string port_file = argument(argc, argv, "--port-file", "");
  const std::string crash_name = argument(argc, argv, "--crash-point", "");
  const bool run_forever = has_flag(argc, argv, "--run-forever");

  ServiceConfig config;
  config.worker_threads = workers;
  config.max_sessions = max_sessions;
  config.persist = !store_path.empty();
  const Result<CrashPoint> crash = parse_crash_point(crash_name);
  if (!crash.ok()) {
    std::fprintf(stderr, "%s\n", crash.status().to_string().c_str());
    return 1;
  }
  config.crash_point = crash.value();

  const Result<std::shared_ptr<PlannerService>> service = PlannerService::start(config, store_path);
  if (!service.ok()) {
    std::fprintf(stderr, "service start failed: %s\n", service.status().to_string().c_str());
    return 1;
  }
  ServerConfig server_config;
  server_config.port = port;
  server_config.bind_address = bind_address;
  server_config.max_sessions = max_sessions;
  const Result<std::unique_ptr<PlanningServer>> server =
      PlanningServer::start(service.value(), server_config);
  if (!server.ok()) {
    std::fprintf(stderr, "server start failed: %s\n", server.status().to_string().c_str());
    return 1;
  }
  std::printf("NRP_SERVER_READY port=%u epoch=%llu boot=%llu\n", server.value()->port(),
              static_cast<unsigned long long>(service.value()->epoch().value()),
              static_cast<unsigned long long>(service.value()->boot().value()));
  std::fflush(stdout);
  if (!port_file.empty()) {
    std::ofstream out(port_file, std::ios::trunc);
    out << server.value()->port() << ' ' << service.value()->epoch().value() << ' '
        << service.value()->boot().value() << '\n';
    out.flush();
  }

  if (run_forever) {
    while (true) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
  }
  int character = 0;
  while ((character = std::getchar()) != EOF) {
    (void)character;
  }
  (void)server.value()->shutdown();
  (void)service.value()->shutdown();
  std::printf("NRP_SERVER_STOPPED\n");
  return 0;
}
