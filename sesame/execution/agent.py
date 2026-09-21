"""Stage 4 Execution Agent — executes bypass plan in QEMU VM with retry."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from sesame.domain.llm_result import BypassPlan
from sesame.execution.prompts import assemble_execution_context, STAGE4_EXECUTION_PROMPT
from sesame.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ExecutionStep:
    step_num: int
    command: str
    target: str  # "vm" | "host"
    result: str
    success: bool
    timestamp: float


@dataclass
class ExecutionResult:
    success: bool
    session_state: dict = field(default_factory=dict)
    executed_commands: list = field(default_factory=list)
    attempts: int = 0
    strategy_used: str = ""
    error: str = ""


class ExecutionAgent:
    """Executes a bypass plan in the QEMU VM with LLM-guided reasoning."""

    def __init__(self, llm_client, qemu, bundle):
        self.llm = llm_client
        self.qemu = qemu
        self.bundle = bundle
        self.execution_log: list[ExecutionStep] = []

    def execute_bypass_plan(
        self,
        plan: BypassPlan,
        architecture=None,
        max_rounds: int = 20,
    ) -> ExecutionResult:
        """Execute the bypass plan. Returns ExecutionResult with session state."""
        logger.info("=" * 60)
        logger.info("=== Stage 4: Execution Agent ===")
        logger.info("=" * 60)
        logger.info(f"Strategy: {plan.bypass_strategy}")
        logger.info(f"VM commands: {len(plan.vm_commands)}")
        logger.info(f"Host commands: {len(plan.host_commands)}")

        # Try primary strategy
        result = self._run_agent_loop(plan, architecture, max_rounds)
        if result and result.get("success"):
            logger.info("Stage 4 SUCCESS: bypass executed successfully")
            return self._build_result(result, plan.bypass_strategy, attempts=1)

        # Try fallback strategies
        for i, fallback in enumerate(plan.fallback_strategies):
            logger.info(f"Trying fallback strategy {i+1}: {fallback}")
            fallback_plan = BypassPlan(
                bypass_strategy=fallback,
                description=f"Fallback: {fallback}",
                vm_commands=[],
                host_commands=[],
                credentials_to_try=plan.credentials_to_try,
                expected_session=plan.expected_session,
                fallback_strategies=[],
                confidence=0.0,
            )
            result = self._run_agent_loop(fallback_plan, architecture, max_rounds)
            if result and result.get("success"):
                logger.info(f"Stage 4 SUCCESS via fallback: {fallback}")
                return self._build_result(result, fallback, attempts=i + 2)

        logger.info("Stage 4 FAILED: all strategies exhausted")
        return ExecutionResult(
            success=False,
            executed_commands=[s.__dict__ for s in self.execution_log],
            attempts=1 + len(plan.fallback_strategies),
            strategy_used=plan.bypass_strategy,
            error="All strategies failed",
        )

    def _run_agent_loop(
        self,
        plan: BypassPlan,
        architecture,
        max_rounds: int,
    ) -> dict | None:
        """Run LLM agent with execution tools."""
        context = assemble_execution_context(plan, architecture)
        prompt = STAGE4_EXECUTION_PROMPT.format(
            context=context.replace("{", "{{").replace("}", "}}")
        )

        logger.info(f"Stage 4 prompt ({len(prompt)} chars)")
        result = self.llm.execute_bypass_with_tools(
            prompt,
            rootfs_path=self.bundle.input.rootfs_path,
            bundle=self.bundle,
            max_rounds=max_rounds,
        )

        if result:
            logger.info(f"Stage 4 agent result: success={result.get('success')}")
            if result.get("session_state"):
                logger.info(f"  session_state: {json.dumps(result.get('session_state', {}), indent=2)}")
        else:
            logger.info("Stage 4 agent returned no result")

        return result

    def _build_result(self, result: dict, strategy: str, attempts: int) -> ExecutionResult:
        session_state = result.get("session_state", {})
        # Normalize session_state structure
        if "cookies" not in session_state:
            session_state = {"cookies": session_state, "url_tokens": {}, "url_token_pattern": ""}

        return ExecutionResult(
            success=True,
            session_state=session_state,
            executed_commands=[s.__dict__ for s in self.execution_log],
            attempts=attempts,
            strategy_used=strategy,
        )
