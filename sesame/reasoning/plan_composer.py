from sesame.domain.primitives import SolutionPlan


def compose_solution_plan(mismatches, primitive_plans):
    return SolutionPlan(
        mismatch_layers=[m.layer.value for m in mismatches],
        primitives=primitive_plans,
        expected_outcomes=[f"recover_testability_via_{p.primitive.value}" for p in primitive_plans],
    )

