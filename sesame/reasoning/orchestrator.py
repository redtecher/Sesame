import time

from sesame.domain.report import BypassPlanOutput, EnablementResult, FuzzArtifact, PipelineMetrics, ReachabilityLevel, RehostingMetrics, StageMetrics, TestEnablementReport, TestTarget, VerificationTrace
from sesame.primitives.runtime_evidence import build_fuzz_artifacts
from sesame.reasoning.hypothesis_ranker import rank_hypotheses
from sesame.reasoning.mismatch_locator import locate_mismatches
from sesame.reasoning.plan_composer import compose_solution_plan
from sesame.reasoning.primitive_selector import select_primitives
from sesame.verification.report import build_summary
from sesame.verification.runtime import evaluate_targets
from sesame.utils.logger import get_logger

logger = get_logger(__name__)


def build_enablement_result(bundle, surface, semantic_context, settings):
    # Locate mismatches (LLM-driven + heuristic augmentation)
    mismatches = locate_mismatches(surface=surface, semantic_context=semantic_context)
    primitive_plans = select_primitives(mismatches=mismatches)
    solution_plan = compose_solution_plan(mismatches=mismatches, primitive_plans=primitive_plans)
    hypotheses = rank_hypotheses(mismatches=mismatches, primitive_plans=primitive_plans)

    # Use session state recovered by the LLM Agent in Stage 3
    agent_session_state = getattr(semantic_context, "agent_session_state", {})

    if agent_session_state:
        logger.info(f"Using Agent-recovered session state: cookies={list(agent_session_state.get('cookies', {}).keys())}, url_tokens={list(agent_session_state.get('url_tokens', {}).keys())}")
    else:
        logger.info("No Agent session state available — evaluating targets without authentication")

    # Capture "before" state from initial discovery probes (pre-recovery reachability)
    initial_targets = surface.test_targets
    before_pages = sum(1 for t in initial_targets if t.target_type == "page" and t.reachability != ReachabilityLevel.UNREACHABLE)
    before_reachable = sum(1 for t in initial_targets if t.reachability != ReachabilityLevel.UNREACHABLE)
    before_post_auth = sum(1 for t in initial_targets if t.reachability in {ReachabilityLevel.POST_AUTH_PAGE, ReachabilityLevel.API_READY, ReachabilityLevel.FUZZ_READY})
    before_fuzzable = sum(1 for t in initial_targets if t.reachability == ReachabilityLevel.FUZZ_READY)
    logger.info(f"Before recovery: {before_pages} pages, {before_reachable} reachable, {before_post_auth} post-auth, {before_fuzzable} fuzzable")

    # Phase 4: Evaluate all targets with the recovered session
    t_verify = time.monotonic()
    targets, session_state = evaluate_targets(
        bundle=bundle, surface=surface, session_state=agent_session_state,
    )
    verify_time = time.monotonic() - t_verify

    # Build fuzz artifacts from recovered targets
    artifacts = build_fuzz_artifacts(targets=targets, hypotheses=hypotheses, session_state=session_state)

    # Compute metrics — "before" comes from initial discovery probes, "after" from post-recovery evaluation
    rehosting_metrics = RehostingMetrics(
        reachable_services_before=before_reachable,
        reachable_services_after=sum(1 for t in targets if t.reachability != ReachabilityLevel.UNREACHABLE),
        reachable_pages_before=before_pages,
        reachable_pages_after=sum(1 for t in targets if t.target_type == "page" and t.reachability != ReachabilityLevel.UNREACHABLE),
        post_auth_targets_before=before_post_auth,
        post_auth_targets_after=sum(1 for t in targets if t.reachability in {ReachabilityLevel.POST_AUTH_PAGE, ReachabilityLevel.API_READY, ReachabilityLevel.FUZZ_READY}),
        fuzzable_targets_before=before_fuzzable,
        fuzzable_targets_after=sum(1 for t in targets if t.reachability == ReachabilityLevel.FUZZ_READY),
    )

    logger.info(f"Metrics: pages_after={rehosting_metrics.reachable_pages_after}, post_auth={rehosting_metrics.post_auth_targets_after}, fuzzable={rehosting_metrics.fuzzable_targets_after}")

    pipeline_metrics = PipelineMetrics(
        verification=StageMetrics(wall_time_s=verify_time),
    )

    report = TestEnablementReport(
        summary=build_summary(targets=targets, metrics=rehosting_metrics, hypotheses=hypotheses),
        semantics=semantic_context.finding,
        hypotheses=hypotheses,
        traces=[VerificationTrace(method="solution_plan", target="global", observation=str(solution_plan.expected_outcomes), confirms=[m.layer for m in mismatches])],
        runtime_state_evidence=getattr(surface, "runtime_state_evidence", []),
    )

    # Extract bypass plan from semantic context
    bypass_plan_raw = getattr(semantic_context, "bypass_plan", None)
    bypass_plan = BypassPlanOutput()
    if bypass_plan_raw:
        try:
            bypass_plan = BypassPlanOutput(
                bypass_strategy=bypass_plan_raw.bypass_strategy,
                description=bypass_plan_raw.description,
                vm_commands=bypass_plan_raw.vm_commands,
                host_commands=bypass_plan_raw.host_commands,
                credentials_to_try=bypass_plan_raw.credentials_to_try,
                expected_session=bypass_plan_raw.expected_session,
                fallback_strategies=bypass_plan_raw.fallback_strategies,
                confidence=bypass_plan_raw.confidence,
            )
        except Exception:
            pass

    return EnablementResult(
        report=report, targets=targets, artifacts=artifacts,
        metrics=rehosting_metrics, pipeline_metrics=pipeline_metrics,
        bypass_plan=bypass_plan,
    )
