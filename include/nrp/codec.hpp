// Network Recovery Planner - canonical decoders for domain objects.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef NRP_CODEC_HPP
#define NRP_CODEC_HPP

#include "nrp/domain.hpp"
#include "nrp/plan.hpp"

namespace nrp {

/// Every decoder is total: it either consumes its input exactly and produces a
/// structurally valid value, or it fails with a status. Declared sizes are
/// checked against the model limits before any allocation happens.
Status decode_definition(CanonicalReader& reader, const ModelLimits& limits, FabricDefinition* out);
Status decode_evidence(CanonicalReader& reader, const ModelLimits& limits, EvidenceBundle* out);
Status decode_authority(CanonicalReader& reader, const ModelLimits& limits, AuthorityVector* out);
Status decode_policy(CanonicalReader& reader, PlanPolicy* out);
Status decode_plan_request_body(CanonicalReader& reader, const ModelLimits& limits, PlanRequest* out);

void encode_fence(const Fence& fence, CanonicalWriter& writer);
Status decode_fence(CanonicalReader& reader, Fence* out);

void encode_explanation(CanonicalWriter& writer, const Explanation& explanation);
Status decode_explanation(CanonicalReader& reader, const ModelLimits& limits, Explanation* out);

void encode_plan(const RecoveryPlan& plan, CanonicalWriter& writer);
Status decode_plan(CanonicalReader& reader, const ModelLimits& limits, RecoveryPlan* out);

}  // namespace nrp

#endif  // NRP_CODEC_HPP
