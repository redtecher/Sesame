from sesame.domain.primitives import PrimitivePlan, SolutionPrimitive


def select_primitives(mismatches) -> list[PrimitivePlan]:
    plans: list[PrimitivePlan] = []
    for mismatch in mismatches:
        if mismatch.layer.value == "source_mismatch":
            plans.append(PrimitivePlan(primitive=SolutionPrimitive.RECOVER_SOURCE, goal=mismatch.title, required_inputs=mismatch.evidence, verification_steps=["check config/file presence", "compare runtime path with rootfs path", "verify auth-gated target changes after source confirmation"]))
        elif mismatch.layer.value == "representation_mismatch":
            plans.append(PrimitivePlan(primitive=SolutionPrimitive.NORMALIZE_REPRESENTATION, goal=mismatch.title, required_inputs=mismatch.evidence, verification_steps=["verify stored vs submitted representation", "check hashes and encodings", "replay auth request with same state prerequisites"]))
        elif mismatch.layer.value == "transfer_mismatch":
            plans.append(PrimitivePlan(primitive=SolutionPrimitive.TRACE_TRANSFER, goal=mismatch.title, required_inputs=mismatch.evidence, verification_steps=["trace state propagation across components", "compare login redirect and post-auth target behavior", "replay auth flow"]))
        else:
            plans.append(PrimitivePlan(primitive=SolutionPrimitive.COLLECT_RUNTIME_EVIDENCE, goal=mismatch.title, required_inputs=mismatch.evidence, verification_steps=["collect read-only gdb evidence", "align runtime buffers with static expectations", "confirm whether target reaches API_READY or FUZZ_READY"]))
    return plans
