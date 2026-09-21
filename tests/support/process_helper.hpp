// Network Recovery Planner - test-only process control helpers.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Real operating system processes and real loopback sockets are used by the
// multiprocess suite; threads are never accepted as a substitute.
#ifndef NRP_TEST_PROCESS_HELPER_HPP
#define NRP_TEST_PROCESS_HELPER_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace nrp::test {

class ChildProcess {
 public:
  ChildProcess() = default;
  ~ChildProcess();
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;

  /// Starts a process. When stdin_pipe is true the child's stdin is a pipe owned
  /// by this object and close_stdin() makes the child observe EOF.
  bool start(const std::string& executable, const std::vector<std::string>& arguments,
             bool stdin_pipe = false);
  bool valid() const { return pid_ != 0; }
  bool running() const;
  /// Blocks until the process exits and returns its exit code (-1 if unknown).
  int wait();
  /// Hard, immediate termination (no graceful shutdown path is executed).
  bool kill_hard();
  void close_stdin();
  std::uint64_t pid() const { return pid_; }

 private:
  std::uint64_t pid_ = 0;
  void* handle_ = nullptr;
  void* stdin_write_ = nullptr;
};

/// Reads a text file, returning an empty string when it does not exist.
std::string read_text_file(const std::string& path);

/// Bounded readiness probe: waits until the file exists and starts with the
/// expected prefix. It fails explicitly instead of waiting forever.
bool wait_for_file(const std::string& path, const std::string& expected_prefix,
                   int max_attempts, int sleep_milliseconds, std::string* content);

}  // namespace nrp::test

#endif  // NRP_TEST_PROCESS_HELPER_HPP
