import time

from sesame.bootstrap import Settings
from sesame.discovery.service import discover_surface
from sesame.discovery.lua_decompiler import batch_decompile_lua
from sesame.domain.report import PipelineMetrics, StageMetrics, ReachabilityLevel
from sesame.reasoning.orchestrator import build_enablement_result
from sesame.semantics.orchestrator import build_semantic_context
from sesame.semantics.agent_tools import set_decompiled_cache
from sesame.utils.logger import get_logger

logger = get_logger(__name__)


def run_enablement_pipeline(bundle, settings: Settings):
    metrics = PipelineMetrics()
    t_start = time.monotonic()

    # Pre-process: decompile Fate/Z encrypted Lua files (Xiaomi/MIWiFi)
    cache_dir = batch_decompile_lua(rootfs_path=bundle.input.rootfs_path)
    if cache_dir:
        set_decompiled_cache(cache_dir)

    # Phase 1: Surface Discovery
    t0 = time.monotonic()
    surface = discover_surface(bundle=bundle, settings=settings)
    metrics.discovery = StageMetrics(wall_time_s=time.monotonic() - t0)
    logger.info(f"Phase 1 (Discovery): {metrics.discovery.wall_time_s:.1f}s")

    # Phase 2: LLM-Guided Semantic Analysis (Stage 1-3)
    t0 = time.monotonic()
    semantic_context, llm_client = build_semantic_context(bundle=bundle, surface=surface, settings=settings)
    semantic_time = time.monotonic() - t0

    # Collect LLM metrics — split by stage using tool call names as heuristic
    stage1_tool_names = {"search_files", "read_file", "grep_files"}
    stage3_tool_names = {"http_request", "browser_navigate"}

    s1_calls = {k: v for k, v in llm_client.tool_call_counts.items() if k in stage1_tool_names}
    s3_calls = {k: v for k, v in llm_client.tool_call_counts.items() if k in stage3_tool_names}
    s1_total = sum(s1_calls.values())
    s3_total = sum(s3_calls.values())
    all_tool_total = s1_total + s3_total

    # Approximate token split: proportional to tool calls (Stage 2 has 0 tool calls)
    ratio_s1 = s1_total / all_tool_total if all_tool_total > 0 else 0.5
    ratio_s3 = s3_total / all_tool_total if all_tool_total > 0 else 0.5

    metrics.stage1_architecture = StageMetrics(
        wall_time_s=semantic_time * ratio_s1 if all_tool_total > 0 else 0,
        input_tokens=int(llm_client.total_input_tokens * ratio_s1) if all_tool_total > 0 else 0,
        output_tokens=int(llm_client.total_output_tokens * ratio_s1) if all_tool_total > 0 else 0,
        tool_calls=s1_calls,
    )
    metrics.stage2_mismatch = StageMetrics(
        wall_time_s=semantic_time * (1 - ratio_s1 - ratio_s3) if all_tool_total > 0 else 0,
        input_tokens=int(llm_client.total_input_tokens * (1 - ratio_s1 - ratio_s3)) if all_tool_total > 0 else 0,
        output_tokens=int(llm_client.total_output_tokens * (1 - ratio_s1 - ratio_s3)) if all_tool_total > 0 else 0,
    )
    metrics.stage3_recovery = StageMetrics(
        wall_time_s=semantic_time * ratio_s3 if all_tool_total > 0 else 0,
        input_tokens=int(llm_client.total_output_tokens * ratio_s3) if all_tool_total > 0 else 0,
        output_tokens=int(llm_client.total_output_tokens * ratio_s3) if all_tool_total > 0 else 0,
        tool_calls=s3_calls,
    )
    logger.info(f"Phase 2 (LLM Analysis): {semantic_time:.1f}s total, "
                f"S1={metrics.stage1_architecture.wall_time_s:.1f}s, "
                f"S2={metrics.stage2_mismatch.wall_time_s:.1f}s, "
                f"S3={metrics.stage3_recovery.wall_time_s:.1f}s")

    # Determine recovery technique (highest escalation level used)
    if s3_calls.get("browser_navigate", 0) > 0:
        metrics.recovery_technique = "Browser"
    elif s3_calls.get("http_request", 0) > 0:
        metrics.recovery_technique = "HTTP"

    # Compute mismatch distribution across 4 layers
    mismatch_dist: dict[str, int] = {}
    for m in semantic_context.llm_mismatches:
        layer = m.layer.lower()
        mismatch_dist[layer] = mismatch_dist.get(layer, 0) + 1
    metrics.mismatch_distribution = mismatch_dist

    # Phase 3: Mismatch Localization (reasoning without verification)
    t0 = time.monotonic()
    enablement = build_enablement_result(
        bundle=bundle, surface=surface, semantic_context=semantic_context, settings=settings,
    )
    reasoning_time = time.monotonic() - t0
    logger.info(f"Phase 3 (Reasoning): {reasoning_time:.1f}s")

    # Phase 4 timing — subtract reasoning time from the total verification time
    metrics.verification = StageMetrics(
        wall_time_s=max(0, enablement.pipeline_metrics.verification.wall_time_s),
    )

    # Propagate metrics to result
    metrics.total_wall_time_s = time.monotonic() - t_start
    enablement.pipeline_metrics = metrics

    logger.info(f"Total pipeline: {metrics.total_wall_time_s:.1f}s, "
                f"recovery_technique={metrics.recovery_technique}, "
                f"tokens={llm_client.total_input_tokens}+{llm_client.total_output_tokens}")

    return enablement
