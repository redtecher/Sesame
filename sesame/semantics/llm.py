import json
import re

import httpx

from sesame.domain.llm_result import AuthArchitecture, LLMMismatchItem, RecoveryPlan, RecoveryStep
from sesame.semantics.config import SemanticRuntimeConfig
from sesame.utils.logger import get_logger

logger = get_logger(__name__)


def _parse_dsml_tool_calls(text: str) -> list[tuple[str, dict]] | None:
    """Parse DeepSeek's proprietary <｜｜DSML｜｜tool_calls> format.

    Returns list of (function_name, arguments_dict) or None if text is not DSML format.
    Example input:
        <｜｜DSML｜｜tool_calls>
        <｜｜DSML｜｜invoke name="read_file">
        <｜｜DSML｜｜parameter name="max_chars" string="false">200</｜｜DSML｜｜parameter>
        <｜｜DSML｜｜parameter name="path" string="true">some/file.lua</｜｜DSML｜｜parameter>
        </｜｜DSML｜｜invoke>
        </｜｜DSML｜｜tool_calls>
    """
    if "<｜｜DSML｜｜tool_calls>" not in text:
        return None

    calls = []
    # Match each invoke block
    invoke_pattern = re.compile(r'<｜｜DSML｜｜invoke\s+name="(\w+)">(.*?)</｜｜DSML｜｜invoke>', re.DOTALL)
    param_pattern = re.compile(r'<｜｜DSML｜｜parameter\s+name="(\w+)"[^>]*>(.*?)</｜｜DSML｜｜parameter>', re.DOTALL)

    for invoke_match in invoke_pattern.finditer(text):
        fn_name = invoke_match.group(1)
        invoke_body = invoke_match.group(2)
        args = {}
        for param_match in param_pattern.finditer(invoke_body):
            p_name = param_match.group(1)
            p_value = param_match.group(2).strip()
            # Try to parse as number
            try:
                p_value = int(p_value)
            except ValueError:
                try:
                    p_value = float(p_value)
                except ValueError:
                    pass
            args[p_name] = p_value
        calls.append((fn_name, args))

    return calls if calls else None


def _tool_dispatch(rootfs_path: str, tool_name: str, arguments: dict, bundle=None) -> str:
    """Dispatch a tool call using the agent_tools module."""
    from sesame.semantics.agent_tools import execute_tool

    return execute_tool(rootfs_path, tool_name, arguments, bundle=bundle)


class DeepseekClient:
    def __init__(self, config: SemanticRuntimeConfig):
        self.config = config
        self._client: httpx.Client | None = None
        # Metrics accumulators
        self.total_input_tokens: int = 0
        self.total_output_tokens: int = 0
        self.tool_call_counts: dict[str, int] = {}
        # Per-stage token snapshots: stage_name -> {input, output}
        self.stage_token_snapshots: dict[str, dict[str, int]] = {}

    @property
    def available(self) -> bool:
        return bool(self.config.llm.api_key and self.config.llm.api_base)

    def snapshot_stage(self, stage_name: str) -> None:
        """Snapshot cumulative token counts as the start of a stage."""
        self.stage_token_snapshots[stage_name] = {
            "input_start": self.total_input_tokens,
            "output_start": self.total_output_tokens,
        }

    def get_stage_tokens(self, stage_name: str) -> dict[str, int]:
        """Get token delta for a stage (input, output, total)."""
        snap = self.stage_token_snapshots.get(stage_name, {})
        return {
            "input_tokens": self.total_input_tokens - snap.get("input_start", 0),
            "output_tokens": self.total_output_tokens - snap.get("output_start", 0),
            "total_tokens": (self.total_input_tokens + self.total_output_tokens)
                            - snap.get("input_start", 0) - snap.get("output_start", 0),
        }

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=120.0)
        return self._client

    def _call(self, prompt: str) -> dict | None:
        if not self.available:
            return None
        try:
            logger.info(f"LLM prompt ({len(prompt)} chars):\n{prompt[:2000]}{'...' if len(prompt) > 2000 else ''}")
            req_body = {
                "model": self.config.llm.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": max(self.config.llm.temperature, 0.0),
            }
            resp = self._get_client().post(
                f"{self.config.llm.api_base.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {self.config.llm.api_key}"},
                json=req_body,
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            usage = data.get("usage", {})
            self.total_input_tokens += usage.get("prompt_tokens", 0)
            self.total_output_tokens += usage.get("completion_tokens", 0)
            logger.info(f"LLM response ({len(content)} chars, tokens: {usage.get('prompt_tokens', '?')}+{usage.get('completion_tokens', '?')}):\n{content}")
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                match = re.search(r"\{[\s\S]*\}", content)
                if match:
                    return json.loads(match.group())
                return None
        except Exception as e:
            logger.warning(f"LLM call failed: {type(e).__name__}: {e}")
            return None

    def analyze_architecture_with_tools(self, prompt: str, rootfs_path: str, max_rounds: int = 10) -> dict | None:
        """Stage 1 with tool calling: LLM explores filesystem to understand auth architecture."""
        from sesame.semantics.agent_tools import FILESYSTEM_TOOL_SCHEMAS

        return self._call_with_tools(prompt, FILESYSTEM_TOOL_SCHEMAS, rootfs_path, max_rounds=max_rounds)

    def recover_with_tools(self, prompt: str, rootfs_path: str, bundle, max_rounds: int = 12) -> dict | None:
        """Stage 3 with tool calling: LLM uses runtime tools (HTTP, shell, GDB) to recover auth state."""
        from sesame.semantics.agent_tools import ALL_TOOL_SCHEMAS

        return self._call_with_tools(prompt, ALL_TOOL_SCHEMAS, rootfs_path, bundle=bundle, max_rounds=max_rounds)

    def execute_bypass_with_tools(self, prompt: str, rootfs_path: str, bundle, max_rounds: int = 20) -> dict | None:
        """Stage 4 with execution tools: LLM executes bypass plan in QEMU VM."""
        from sesame.semantics.agent_tools import EXECUTION_TOOL_SCHEMAS

        return self._call_with_tools(prompt, EXECUTION_TOOL_SCHEMAS, rootfs_path, bundle=bundle, max_rounds=max_rounds)

    def _call_with_tools(self, prompt: str, tools: list[dict], rootfs_path: str, bundle=None, max_rounds: int = 10) -> dict | None:
        """ReAct loop: LLM calls tools, gets results, reasons, repeats until final JSON answer."""
        # Add submit_result tool — agent calls this when done
        submit_tool = {
            "type": "function",
            "function": {
                "name": "submit_result",
                "description": "Submit your final analysis. Call this as soon as you have enough information — do NOT keep exploring.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "result": {
                            "type": "object",
                            "description": "Your complete analysis result as JSON matching the required output schema.",
                        }
                    },
                    "required": ["result"],
                },
            },
        }
        all_tools = tools + [submit_tool]

        messages = [
            {"role": "system", "content": (
                "You are a firmware security researcher. Use tools to investigate the firmware.\n"
                "IMPORTANT RULES:\n"
                "1. You MUST call submit_result when you have enough information. This is the ONLY way to finish.\n"
                "2. After 5-8 tool calls, you MUST submit your findings even if incomplete.\n"
                "3. If you found: login URL, auth type, and session mechanism → submit immediately.\n"
                "4. Do NOT read the same file twice. Do NOT over-explore."
            )},
            {"role": "user", "content": prompt},
        ]

        for round_idx in range(max_rounds):
            remaining = max_rounds - round_idx
            # Last 2 rounds: force LLM to output text (no tools) so it must give final answer
            force_no_tools = remaining <= 2

            if remaining == 5:
                messages.append({"role": "user", "content": "[SYSTEM] WARNING: Only 5 rounds left. You MUST call submit_result NOW with whatever you have found."})
            elif remaining == 3:
                messages.append({"role": "user", "content": "[SYSTEM] FINAL WARNING: 3 rounds left. Call submit_result IMMEDIATELY or your work will be lost."})

            try:
                req_body = {
                    "model": self.config.llm.model,
                    "messages": messages,
                    "temperature": max(self.config.llm.temperature, 0.0),
                }
                # NOTE: thinking mode is NOT enabled for agent/tool-calling mode
                # because DeepSeek API rejects tool messages when thinking is on (400 error)
                if force_no_tools:
                    # Remove tools entirely — LLM must output plain text
                    req_body["tool_choice"] = "none"
                    # Inject explicit instruction
                    messages.append({"role": "user", "content": "[SYSTEM] Tool access revoked. Output your analysis as JSON NOW. This is your last chance."})
                else:
                    req_body["tools"] = all_tools
                    req_body["tool_choice"] = "auto"

                resp = self._get_client().post(
                    f"{self.config.llm.api_base.rstrip('/')}/chat/completions",
                    headers={"Authorization": f"Bearer {self.config.llm.api_key}"},
                    json=req_body,
                )
                resp.raise_for_status()
                data = resp.json()
                usage = data.get("usage", {})
                self.total_input_tokens += usage.get("prompt_tokens", 0)
                self.total_output_tokens += usage.get("completion_tokens", 0)
            except Exception as e:
                logger.warning(f"Tool-calling LLM request failed (round {round_idx}): {e}")
                continue

            choice = data["choices"][0]
            msg = choice["message"]

            tool_calls = msg.get("tool_calls") or []
            if tool_calls:
                # DeepSeek v4 requires reasoning_content to be passed back in subsequent requests
                messages.append(msg)
                for tc in tool_calls:
                    fn_name = tc["function"]["name"]
                    try:
                        fn_args = json.loads(tc["function"]["arguments"])
                    except json.JSONDecodeError:
                        fn_args = {}

                    # Agent submitted result
                    if fn_name == "submit_result":
                        result = fn_args.get("result", {})
                        logger.info(f"Agent submitted result via submit_result ({len(json.dumps(result))} chars)")
                        logger.info(f"Result keys: {list(result.keys()) if isinstance(result, dict) else type(result)}")
                        return result

                    logger.info(f"  Tool call [{round_idx}]: {fn_name}({json.dumps(fn_args)[:200]})")
                    self.tool_call_counts[fn_name] = self.tool_call_counts.get(fn_name, 0) + 1
                    result = _tool_dispatch(rootfs_path, fn_name, fn_args, bundle=bundle)
                    logger.info(f"  Tool result ({len(result)} chars): {result[:300]}")
                    messages.append({"role": "tool", "tool_call_id": tc["id"], "content": result})
                continue

            # No tool calls — plain text answer
            content = msg.get("content", "")
            logger.info(f"Agent final answer ({len(content)} chars): {content[:500]}")

            # Handle DeepSeek proprietary DSML tool_calls format
            # DeepSeek sometimes outputs tool calls as text in <｜｜DSML｜｜tool_calls> tags
            # instead of using the standard tool_calls API field
            dsml_calls = _parse_dsml_tool_calls(content)
            if dsml_calls is not None:
                logger.info(f"Parsed {len(dsml_calls)} DSML tool calls from text output")
                messages.append({"role": "assistant", "content": content})
                for tc_name, tc_args in dsml_calls:
                    if tc_name == "submit_result":
                        # Agent may use "result" or "answer" as parameter name
                        result = tc_args.get("result") or tc_args.get("answer") or tc_args.get("data") or {}
                        # DSML parameters are extracted as strings — parse JSON if needed
                        if isinstance(result, str):
                            try:
                                result = json.loads(result)
                            except json.JSONDecodeError:
                                m = re.search(r"\{[\s\S]*\}", result)
                                if m:
                                    try:
                                        result = json.loads(m.group())
                                    except json.JSONDecodeError:
                                        pass
                        if not result or result == {}:
                            # Last resort: try to find JSON in any parameter value
                            for v in tc_args.values():
                                if isinstance(v, str) and "{" in v:
                                    try:
                                        result = json.loads(v)
                                        break
                                    except json.JSONDecodeError:
                                        m2 = re.search(r"\{[\s\S]*\}", v)
                                        if m2:
                                            try:
                                                result = json.loads(m2.group())
                                                break
                                            except json.JSONDecodeError:
                                                pass
                        logger.info(f"Agent submitted result via DSML submit_result ({len(json.dumps(result)) if isinstance(result, dict) else len(str(result))} chars)")
                        return result
                    logger.info(f"  DSML tool call [{round_idx}]: {tc_name}({json.dumps(tc_args)[:200]})")
                    self.tool_call_counts[tc_name] = self.tool_call_counts.get(tc_name, 0) + 1
                    result = _tool_dispatch(rootfs_path, tc_name, tc_args, bundle=bundle)
                    logger.info(f"  Tool result ({len(result)} chars): {result[:300]}")
                    messages.append({"role": "tool", "tool_call_id": f"dsml_{round_idx}_{tc_name}", "content": result})
                continue

            if not content.strip():
                return None
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                match = re.search(r"\{[\s\S]*\}", content)
                if match:
                    try:
                        return json.loads(match.group())
                    except json.JSONDecodeError:
                        pass
                logger.warning(f"Agent returned non-JSON: {content[:200]}")
                return None

        logger.warning(f"Agent reached max rounds ({max_rounds}) without final answer")
        return None

    def analyze_architecture(self, context: str) -> AuthArchitecture:
        from sesame.semantics.llm_stages import STAGE1_PROMPT

        result = self._call(STAGE1_PROMPT.format(context=context.replace("{", "{{").replace("}", "}}")))
        if result:
            try:
                arch = AuthArchitecture(**{k: v for k, v in result.items() if k in AuthArchitecture.model_fields})
            except Exception as e:
                logger.warning(f"Failed to parse architecture: {e}")
                return AuthArchitecture()
        else:
            return AuthArchitecture()
        # Clean login_url: strip leading method prefix if LLM included it
        for prefix in ("POST ", "GET ", "post ", "get "):
            if arch.login_url.startswith(prefix):
                arch.login_url = arch.login_url[len(prefix):]
        return arch

    def analyze_mismatches(self, context: str) -> list[LLMMismatchItem]:
        from sesame.semantics.llm_stages import STAGE2_PROMPT

        result = self._call(STAGE2_PROMPT.format(context=context.replace("{", "{{").replace("}", "}}")))
        if result and "mismatches" in result:
            items = []
            for m in result["mismatches"]:
                try:
                    items.append(LLMMismatchItem(**{k: v for k, v in m.items() if k in LLMMismatchItem.model_fields}))
                except Exception:
                    continue
            return items
        return []

    def generate_recovery_plan(self, context: str) -> RecoveryPlan:
        from sesame.semantics.llm_stages import STAGE3_PROMPT
        from urllib.parse import parse_qs

        result = self._call(STAGE3_PROMPT.format(context=context.replace("{", "{{").replace("}", "}}")))
        if result:
            try:
                steps = []
                for s in result.get("steps", []):
                    clean = {}
                    for k, v in s.items():
                        if k not in RecoveryStep.model_fields:
                            continue
                        field_ann = RecoveryStep.model_fields[k].annotation
                        expects_dict = field_ann is dict or (hasattr(field_ann, "__origin__") and field_ann.__origin__ is dict)

                        if v is None:
                            if expects_dict:
                                v = {}
                            elif field_ann is list or (hasattr(field_ann, "__origin__") and field_ann.__origin__ is list):
                                v = []
                            elif field_ann is bool:
                                v = False
                            else:
                                v = ""
                        elif expects_dict and isinstance(v, str):
                            if "=" in v and "&" in v:
                                parsed = parse_qs(v, keep_blank_values=True)
                                v = {kk: vv[0] for kk, vv in parsed.items()}
                            elif "=" in v:
                                kk, vv = v.split("=", 1)
                                v = {kk.strip(): vv.strip()}
                            elif v.startswith("{"):
                                try:
                                    import json
                                    v = json.loads(v)
                                except Exception:
                                    v = {}
                            else:
                                v = {}
                        elif isinstance(v, dict):
                            v = {str(dk): str(dv) for dk, dv in v.items()}
                        clean[k] = v
                    steps.append(RecoveryStep(**clean))
                plan_kwargs = {k: v for k, v in result.items() if k in RecoveryPlan.model_fields and k != "steps"}
                return RecoveryPlan(steps=steps, **plan_kwargs)
            except Exception as e:
                logger.warning(f"Failed to parse recovery plan: {e}")
        return RecoveryPlan()
