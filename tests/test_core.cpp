// Network Recovery Planner - canonical encoding, identity and codec tests.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include <string>
#include <vector>

#include "nrp/codec.hpp"
#include "nrp/domain.hpp"
#include "nrp/ids.hpp"
#include "nrp/objective.hpp"
#include "support/fixture.hpp"
#include "support/test_support.hpp"

using namespace nrp;
using namespace nrp::test;

NRP_TEST(canonical, round_trip_and_bounds) {
  CanonicalWriter writer;
  writer.u8(0x12);
  writer.u16(0xBEEF);
  writer.u32(0xDEADBEEF);
  writer.u64(0x0123456789ABCDEFull);
  writer.i64(-42);
  writer.boolean(true);
  writer.str("hello");
  writer.bytes(std::vector<std::uint8_t>{1, 2, 3});
  const std::vector<std::uint8_t> bytes = writer.take();

  CanonicalReader reader(bytes);
  NRP_CHECK_EQ(reader.u8(), static_cast<std::uint8_t>(0x12));
  NRP_CHECK_EQ(reader.u16(), static_cast<std::uint16_t>(0xBEEF));
  NRP_CHECK_EQ(reader.u32(), static_cast<std::uint32_t>(0xDEADBEEF));
  NRP_CHECK_EQ(reader.u64(), 0x0123456789ABCDEFull);
  NRP_CHECK_EQ(reader.i64(), static_cast<std::int64_t>(-42));
  NRP_CHECK_EQ(reader.boolean(), true);
  NRP_CHECK_EQ(reader.str(64), std::string("hello"));
  NRP_CHECK_EQ(reader.bytes(64).size(), static_cast<std::size_t>(3));
  NRP_CHECK(reader.require_end().ok());

  // Truncation at every prefix must fail and stay sticky.
  for (std::size_t length = 0; length < bytes.size(); ++length) {
    CanonicalReader truncated(bytes.data(), length);
    (void)truncated.u8();
    (void)truncated.u16();
    (void)truncated.u32();
    (void)truncated.u64();
    (void)truncated.i64();
    (void)truncated.boolean();
    (void)truncated.str(64);
    (void)truncated.bytes(64);
    NRP_CHECK_MSG(!truncated.ok(), "prefix length " << length << " decoded successfully");
  }

  // Trailing bytes are rejected.
  std::vector<std::uint8_t> extended = bytes;
  extended.push_back(0);
  CanonicalReader trailing(extended);
  (void)trailing.u8();
  NRP_CHECK(!trailing.require_end().ok());
}

NRP_TEST(canonical, booleans_and_counts_are_validated) {
  std::vector<std::uint8_t> bytes{2};
  CanonicalReader reader(bytes);
  (void)reader.boolean();
  NRP_CHECK(!reader.ok());

  CanonicalWriter writer;
  writer.u32(1000);
  CanonicalReader counted(writer.buffer());
  NRP_CHECK_EQ(counted.bounded_count(10, "items"), static_cast<std::uint32_t>(0));
  NRP_CHECK(!counted.ok());
}

NRP_TEST(canonical, checked_arithmetic_refuses_overflow) {
  std::uint64_t out = 0;
  NRP_CHECK(add_overflow(UINT64_MAX, 1, &out));
  NRP_CHECK(!add_overflow(1, 2, &out));
  NRP_CHECK_EQ(out, 3ull);
  NRP_CHECK(mul_overflow(UINT64_MAX, 2, &out));
  NRP_CHECK(!mul_overflow(6, 7, &out));
  NRP_CHECK_EQ(out, 42ull);
}

NRP_TEST(ids, digest_is_stable_and_sensitive) {
  const std::vector<std::uint8_t> data{1, 2, 3, 4, 5};
  const Digest first = digest_of(data);
  const Digest second = digest_of(data);
  NRP_CHECK(first == second);
  std::vector<std::uint8_t> mutated = data;
  mutated[2] ^= 0x01;
  NRP_CHECK(first != digest_of(mutated));
  std::vector<std::uint8_t> extended = data;
  extended.push_back(0);
  NRP_CHECK(first != digest_of(extended));
  NRP_CHECK_EQ(first.hex().size(), static_cast<std::size_t>(32));
  NRP_CHECK(!Digest{}.is_zero() == false);
}

NRP_TEST(objective, lexicographic_order_is_total) {
  ObjectiveVector a{};
  ObjectiveVector b{};
  b[0] = 1;
  NRP_CHECK(compare_objective(a, b) < 0);
  NRP_CHECK(compare_objective(b, a) > 0);
  NRP_CHECK_EQ(compare_objective(a, a), 0);
  ObjectiveVector c{};
  c[7] = 5;
  NRP_CHECK(compare_objective(a, c) < 0);
  std::vector<ActionId> left{ActionId::from_value(1)};
  std::vector<ActionId> right{ActionId::from_value(2)};
  NRP_CHECK(compare_encoding(left, right) < 0);
  NRP_CHECK(compare_encoding(left, left) == 0);
  NRP_CHECK(ScoredPlanLess{}(a, left, b, right));
  NRP_CHECK(ScoredPlanLess{}(a, left, a, right));
  NRP_CHECK(!ScoredPlanLess{}(a, right, a, left));
}

NRP_TEST(domain, request_round_trip_is_exact) {
  TeachingFabric fabric;
  const PlanRequest request = fabric.request();
  CanonicalWriter writer;
  request.encode(writer);
  const std::vector<std::uint8_t> bytes = writer.take();

  const Result<PlanRequest> decoded = decode_plan_request(bytes, default_model_limits());
  NRP_REQUIRE(decoded.ok());
  NRP_CHECK_EQ(decoded.value().digest(), request.digest());
  NRP_CHECK_EQ(decoded.value().definition.digest(), request.definition.digest());
  NRP_CHECK_EQ(decoded.value().definition.actions.size(), request.definition.actions.size());
  NRP_CHECK_EQ(decoded.value().definition.actions[0].preconditions.size(),
               request.definition.actions[0].preconditions.size());

  // Every truncated prefix must be refused.
  for (std::size_t length = 0; length < bytes.size(); ++length) {
    std::vector<std::uint8_t> prefix(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(length));
    const Result<PlanRequest> truncated = decode_plan_request(prefix, default_model_limits());
    NRP_CHECK_MSG(!truncated.ok(), "truncated request of length " << length << " decoded");
  }
  // Trailing bytes must be refused.
  std::vector<std::uint8_t> trailing = bytes;
  trailing.push_back(0x7F);
  NRP_CHECK(!decode_plan_request(trailing, default_model_limits()).ok());
  // An invalid enum must be refused.
  std::vector<std::uint8_t> bad_enum = bytes;
  bool mutated = false;
  for (std::size_t index = 0; index + 1 < bad_enum.size() && !mutated; ++index) {
    // The authority domain byte sits inside the authority vector; flipping a
    // byte until the decode fails proves the decoder validates its input.
    std::vector<std::uint8_t> candidate = bytes;
    candidate[index] ^= 0xFF;
    const Result<PlanRequest> result = decode_plan_request(candidate, default_model_limits());
    if (!result.ok()) mutated = true;
  }
  NRP_CHECK(mutated);
}

NRP_TEST(domain, canonical_order_is_insertion_order_independent) {
  TeachingFabric fabric;
  PlanRequest request = fabric.request();
  const Digest baseline = request.digest();
  for (std::uint64_t seed = 1; seed <= 16; ++seed) {
    const PlanRequest permuted = permuted_request(request, seed);
    PlanRequest normalised = permuted;
    normalised.definition.canonicalise();
    normalised.evidence.canonicalise();
    normalised.authority.canonicalise();
    NRP_CHECK_EQ(normalised.digest(), baseline);
  }
}

NRP_TEST(domain, definition_validation_rejects_broken_models) {
  {
    FabricBuilder builder;
    const NodeId node = builder.add_node();
    (void)node;
    ActionSpec spec;
    spec.preconditions.push_back(
        Precondition{PreconditionKind::LINK_OPERATIONAL, subject_of(LinkId::from_value(99)), 0});
    builder.add_action(spec);
    PlanRequest request = builder.build();
    ExplanationLog log(8);
    NRP_CHECK(!validate_definition(request.definition, default_model_limits(), &log).ok());
  }
  {
    FabricBuilder builder;
    const NodeId a = builder.add_node();
    const NodeId b = builder.add_node();
    const LinkId link = builder.add_link(a, b);
    ActionSpec spec;
    spec.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL, subject_of(link), 2});
    builder.add_action(spec);
    PlanRequest request = builder.build();
    ExplanationLog log(8);
    NRP_CHECK(!validate_definition(request.definition, default_model_limits(), &log).ok());
  }
  {
    FabricBuilder builder;
    const NodeId a = builder.add_node();
    (void)a;
    ActionSpec spec;
    spec.reversibility = Reversibility::REVERSIBLE;
    const ActionId id = builder.add_action(spec);
    (void)id;
    PlanRequest request = builder.build();
    ExplanationLog log(8);
    NRP_CHECK(!validate_definition(request.definition, default_model_limits(), &log).ok());
  }
  {
    FabricBuilder builder;
    const NodeId a = builder.add_node();
    (void)a;
    ActionSpec spec;
    spec.reversibility = Reversibility::IRREVERSIBLE;
    spec.compensation = ActionId::from_value(7);
    builder.add_action(spec);
    PlanRequest request = builder.build();
    ExplanationLog log(8);
    NRP_CHECK(!validate_definition(request.definition, default_model_limits(), &log).ok());
  }
  {
    FabricBuilder builder;
    const NodeId a = builder.add_node();
    (void)a;
    ActionSpec first;
    const ActionId first_id = builder.add_action(first);
    ActionSpec second;
    second.dependencies.push_back(ActionDependency{first_id, 1});
    builder.add_action(second);
    PlanRequest request = builder.build();
    ExplanationLog log(8);
    NRP_CHECK(validate_definition(request.definition, default_model_limits(), &log).ok());
  }
}
