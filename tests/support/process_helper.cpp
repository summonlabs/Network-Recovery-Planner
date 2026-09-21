// Network Recovery Planner - test-only process control helpers.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "support/process_helper.hpp"

#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
#include <csignal>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace nrp::test {

ChildProcess::~ChildProcess() {
  if (pid_ != 0) {
    (void)kill_hard();
    (void)wait();
  }
}

#ifdef _WIN32

bool ChildProcess::start(const std::string& executable,
                         const std::vector<std::string>& arguments,
                         bool stdin_pipe) {
  std::string command = "\"" + executable + "\"";
  for (const std::string& argument : arguments) {
    command += " \"" + argument + "\"";
  }
  std::vector<char> mutable_command(command.begin(), command.end());
  mutable_command.push_back('\0');

  HANDLE stdin_read = nullptr;
  HANDLE stdin_write = nullptr;
  if (stdin_pipe) {
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    if (!CreatePipe(&stdin_read, &stdin_write, &attributes, 0)) return false;
    SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0);
  }

  STARTUPINFOA startup{};
  startup.cb = sizeof(startup);
  if (stdin_pipe) {
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = stdin_read;
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  }
  PROCESS_INFORMATION information{};
  const BOOL created = CreateProcessA(nullptr, mutable_command.data(), nullptr, nullptr,
                                      stdin_pipe ? TRUE : FALSE, 0, nullptr, nullptr, &startup,
                                      &information);
  if (stdin_read != nullptr) CloseHandle(stdin_read);
  if (!created) {
    if (stdin_write != nullptr) CloseHandle(stdin_write);
    return false;
  }
  CloseHandle(information.hThread);
  handle_ = information.hProcess;
  pid_ = static_cast<std::uint64_t>(information.dwProcessId);
  stdin_write_ = stdin_write;
  return true;
}

bool ChildProcess::running() const {
  if (handle_ == nullptr) return false;
  DWORD code = 0;
  if (!GetExitCodeProcess(static_cast<HANDLE>(handle_), &code)) return false;
  return code == STILL_ACTIVE;
}

int ChildProcess::wait() {
  if (handle_ == nullptr) return -1;
  WaitForSingleObject(static_cast<HANDLE>(handle_), INFINITE);
  DWORD code = 0;
  GetExitCodeProcess(static_cast<HANDLE>(handle_), &code);
  CloseHandle(static_cast<HANDLE>(handle_));
  handle_ = nullptr;
  pid_ = 0;
  if (stdin_write_ != nullptr) {
    CloseHandle(static_cast<HANDLE>(stdin_write_));
    stdin_write_ = nullptr;
  }
  return static_cast<int>(code);
}

bool ChildProcess::kill_hard() {
  if (handle_ == nullptr) return false;
  const bool killed = TerminateProcess(static_cast<HANDLE>(handle_), 70) != 0;
  return killed;
}

void ChildProcess::close_stdin() {
  if (stdin_write_ != nullptr) {
    CloseHandle(static_cast<HANDLE>(stdin_write_));
    stdin_write_ = nullptr;
  }
}

#else

bool ChildProcess::start(const std::string& executable,
                         const std::vector<std::string>& arguments,
                         bool stdin_pipe) {
  int pipe_fds[2] = {-1, -1};
  if (stdin_pipe && pipe(pipe_fds) != 0) return false;
  const pid_t pid = fork();
  if (pid < 0) {
    if (stdin_pipe) {
      close(pipe_fds[0]);
      close(pipe_fds[1]);
    }
    return false;
  }
  if (pid == 0) {
    if (stdin_pipe) {
      dup2(pipe_fds[0], STDIN_FILENO);
      close(pipe_fds[0]);
      close(pipe_fds[1]);
    }
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>(executable.c_str()));
    for (const std::string& argument : arguments) {
      argv.push_back(const_cast<char*>(argument.c_str()));
    }
    argv.push_back(nullptr);
    execv(executable.c_str(), argv.data());
    _exit(127);
  }
  if (stdin_pipe) {
    close(pipe_fds[0]);
    stdin_write_ = reinterpret_cast<void*>(static_cast<intptr_t>(pipe_fds[1]));
  }
  pid_ = static_cast<std::uint64_t>(pid);
  handle_ = reinterpret_cast<void*>(static_cast<intptr_t>(pid));
  return true;
}

bool ChildProcess::running() const {
  if (pid_ == 0) return false;
  int status = 0;
  const pid_t result = waitpid(static_cast<pid_t>(pid_), &status, WNOHANG);
  return result == 0;
}

int ChildProcess::wait() {
  if (pid_ == 0) return -1;
  int status = 0;
  waitpid(static_cast<pid_t>(pid_), &status, 0);
  pid_ = 0;
  handle_ = nullptr;
  close_stdin();
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  return -1;
}

bool ChildProcess::kill_hard() {
  if (pid_ == 0) return false;
  return kill(static_cast<pid_t>(pid_), SIGKILL) == 0;
}

void ChildProcess::close_stdin() {
  if (stdin_write_ != nullptr) {
    close(static_cast<int>(reinterpret_cast<intptr_t>(stdin_write_)));
    stdin_write_ = nullptr;
  }
}

#endif

std::string read_text_file(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) return std::string();
  std::ostringstream buffer;
  buffer << input.rdbuf();
  return buffer.str();
}

bool wait_for_file(const std::string& path,
                   const std::string& expected_prefix,
                   int max_attempts,
                   int sleep_milliseconds,
                   std::string* content) {
  for (int attempt = 0; attempt < max_attempts; ++attempt) {
    const std::string text = read_text_file(path);
    if (!text.empty() && (expected_prefix.empty() || text.rfind(expected_prefix, 0) == 0)) {
      if (content != nullptr) *content = text;
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(sleep_milliseconds));
  }
  return false;
}

}  // namespace nrp::test
