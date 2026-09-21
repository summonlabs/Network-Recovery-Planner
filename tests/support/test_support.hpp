// Network Recovery Planner - minimal deterministic test framework.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef NRP_TEST_SUPPORT_HPP
#define NRP_TEST_SUPPORT_HPP

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "nrp/ids.hpp"

namespace nrp::test {

using TestFunction = void (*)();

struct TestCase {
  const char* suite;
  const char* name;
  TestFunction function;
};

inline std::vector<TestCase>& registry() {
  static std::vector<TestCase> cases;
  return cases;
}

inline int& failure_count() {
  static int failures = 0;
  return failures;
}

inline int& check_count() {
  static int checks = 0;
  return checks;
}

inline const char*& current_test() {
  static const char* name = "";
  return name;
}

struct Registrar {
  Registrar(const char* suite, const char* name, TestFunction function) {
    registry().push_back(TestCase{suite, name, function});
  }
};

inline void report_failure(const char* file, int line, const std::string& text) {
  ++failure_count();
  std::fprintf(stderr, "FAIL %s :: %s (%s:%d)\n  %s\n", current_test(), "", file, line, text.c_str());
}

template <class T, class = void>
struct is_streamable : std::false_type {};

template <class T>
struct is_streamable<T,
                     std::void_t<decltype(std::declval<std::ostream&>() << std::declval<const T&>())>>
    : std::true_type {};

/// Types without a stream operator are still printable in failure messages.
template <class T>
std::string stringify(const T& value) {
  if constexpr (is_streamable<T>::value) {
    std::ostringstream out;
    out << value;
    return out.str();
  } else {
    return std::string("<value>");
  }
}

inline std::string stringify(bool value) { return value ? "true" : "false"; }

/// Digests have no stream operator on purpose (they are identities, not text);
/// the test framework renders them through their canonical hex form.
inline std::string stringify(const ::nrp::Digest& value) { return value.hex(); }

/// Strongly typed identities render as KIND:value so a failure message never
/// conflates two different identity spaces.
template <class Tag>
std::string stringify(const ::nrp::StrongId<Tag>& value) {
  return std::to_string(value.value());
}

inline std::string stringify(const ::nrp::Subject& value) { return ::nrp::describe(value); }
inline std::string stringify(const ::nrp::Generation& value) { return std::to_string(value.value); }
inline std::string stringify(const ::nrp::Sequence& value) { return std::to_string(value.value); }

/// Deterministic splitmix64 generator: every property test prints its seed and
/// case index so a failure is reproducible from the log alone.
class Rng {
 public:
  explicit Rng(std::uint64_t seed) : state_(seed) {}

  std::uint64_t next() {
    state_ += 0x9E3779B97F4A7C15ull;
    std::uint64_t value = state_;
    value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ull;
    value = (value ^ (value >> 27)) * 0x94D049BB133111EBull;
    return value ^ (value >> 31);
  }

  std::uint64_t below(std::uint64_t bound) { return bound == 0 ? 0 : next() % bound; }

  bool coin() { return (next() & 1u) != 0u; }

  std::uint64_t seed() const { return seed_; }

 private:
  std::uint64_t state_;
  std::uint64_t seed_ = 0;
};

inline int run_all(int argc, char** argv) {
  const std::string filter = argc > 1 ? argv[1] : std::string();
  int executed = 0;
  for (const TestCase& test : registry()) {
    const std::string full = std::string(test.suite) + "." + test.name;
    if (!filter.empty() && full.find(filter) == std::string::npos) continue;
    current_test() = full.c_str();
    const int before = failure_count();
    test.function();
    ++executed;
    if (failure_count() == before) {
      std::printf("PASS %s\n", full.c_str());
    } else {
      std::printf("FAIL %s\n", full.c_str());
    }
  }
  std::printf("summary: %d tests executed, %d checks, %d failures\n", executed, check_count(),
              failure_count());
  if (executed == 0) {
    std::printf("no tests matched the filter\n");
    return 2;
  }
  return failure_count() == 0 ? 0 : 1;
}

}  // namespace nrp::test

#define NRP_TEST(suite, name)                                                            \
  static void nrp_test_##suite##_##name();                                                \
  static ::nrp::test::Registrar nrp_registrar_##suite##_##name(#suite, #name,             \
                                                              &nrp_test_##suite##_##name); \
  static void nrp_test_##suite##_##name()

#define NRP_CHECK(condition)                                                              \
  do {                                                                                    \
    ++::nrp::test::check_count();                                                          \
    if (!(condition)) {                                                                    \
      ::nrp::test::report_failure(__FILE__, __LINE__, "check failed: " #condition);         \
    }                                                                                      \
  } while (false)

#define NRP_CHECK_MSG(condition, message)                                                  \
  do {                                                                                     \
    ++::nrp::test::check_count();                                                           \
    if (!(condition)) {                                                                     \
      std::ostringstream nrp_detail;                                                        \
      nrp_detail << "check failed: " #condition << " | " << message;                         \
      ::nrp::test::report_failure(__FILE__, __LINE__, nrp_detail.str());                     \
    }                                                                                       \
  } while (false)

#define NRP_CHECK_EQ(actual, expected)                                                     \
  do {                                                                                     \
    ++::nrp::test::check_count();                                                           \
    const auto& nrp_actual = (actual);                                                       \
    const auto& nrp_expected = (expected);                                                    \
    if (!(nrp_actual == nrp_expected)) {                                                      \
      std::ostringstream nrp_detail;                                                          \
      nrp_detail << #actual << " == " << #expected << " | actual="                              \
                 << ::nrp::test::stringify(nrp_actual)                                          \
                 << " expected=" << ::nrp::test::stringify(nrp_expected);                        \
      ::nrp::test::report_failure(__FILE__, __LINE__, nrp_detail.str());                        \
    }                                                                                         \
  } while (false)

#define NRP_REQUIRE(condition)                                                             \
  do {                                                                                     \
    ++::nrp::test::check_count();                                                           \
    if (!(condition)) {                                                                     \
      ::nrp::test::report_failure(__FILE__, __LINE__, "requirement failed: " #condition);     \
      return;                                                                                \
    }                                                                                        \
  } while (false)

#endif  // NRP_TEST_SUPPORT_HPP
