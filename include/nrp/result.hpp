// Network Recovery Planner - status/result plumbing.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef NRP_RESULT_HPP
#define NRP_RESULT_HPP

#include <optional>
#include <string>
#include <utility>

namespace nrp {

/// Machine-checkable failure classes. Every externally visible failure maps to
/// exactly one of these; nothing is silently converted into success.
enum class StatusCode : std::uint8_t {
  OK = 0,
  INVALID_ARGUMENT = 1,   // caller handed structurally invalid data
  OUT_OF_RANGE = 2,        // a bounded quantity was exceeded / would overflow
  CORRUPT = 3,             // integrity check or structural check failed
  UNSUPPORTED = 4,         // well-formed but outside the supported class
  IO_ERROR = 5,            // OS level failure
  EXHAUSTED = 6,           // bounded resource limit reached
  NOT_FOUND = 7,           // referenced entity does not exist
  STATE_MISMATCH = 8,      // generation/epoch/authority mismatch
  PROTOCOL_ERROR = 9,      // framing/codec level violation
  CLOSED = 10,             // handle/connection already shut down
  CONFLICT = 11,           // contradictory facts for the same subject
};

const char* to_string(StatusCode code) noexcept;

class Status {
 public:
  Status() = default;
  Status(StatusCode code, std::string message) : code_(code), message_(std::move(message)) {}

  static Status success() { return Status(); }
  static Status error(StatusCode code, std::string message) {
    return Status(code, std::move(message));
  }

  [[nodiscard]] bool ok() const noexcept { return code_ == StatusCode::OK; }
  StatusCode code() const noexcept { return code_; }
  const std::string& message() const noexcept { return message_; }
  explicit operator bool() const noexcept { return ok(); }

  std::string to_string() const {
    return std::string(nrp::to_string(code_)) + (message_.empty() ? std::string() : ": " + message_);
  }

 private:
  StatusCode code_ = StatusCode::OK;
  std::string message_;
};

/// Result carrier. Exactly one of (value, non-OK status) is ever meaningful;
/// constructing from a failure status leaves the value disengaged.
template <class T>
class Result {
 public:
  Result(T value) : value_(std::move(value)) {}
  Result(Status status) : status_(std::move(status)) {}

  bool ok() const noexcept { return value_.has_value(); }
  const Status& status() const noexcept { return status_; }

  T& value() { return *value_; }
  const T& value() const { return *value_; }
  T&& take() { return std::move(*value_); }

  T value_or(T fallback) const { return value_.has_value() ? *value_ : std::move(fallback); }

 private:
  std::optional<T> value_;
  Status status_ = Status::error(StatusCode::INVALID_ARGUMENT, "result not initialised");
};

}  // namespace nrp

#endif  // NRP_RESULT_HPP
