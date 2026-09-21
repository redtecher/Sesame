from sesame.domain.llm_result import LLMMismatchItem
from sesame.domain.mismatch import MismatchFinding, MismatchLayer
from sesame.utils.logger import get_logger

logger = get_logger(__name__)

LAYER_MAP = {
    "source_mismatch": MismatchLayer.SOURCE,
    "representation_mismatch": MismatchLayer.REPRESENTATION,
    "transfer_mismatch": MismatchLayer.TRANSFER,
    "consumption_mismatch": MismatchLayer.CONSUMPTION,
}


def locate_mismatches(surface, semantic_context) -> list[MismatchFinding]:
    findings: list[MismatchFinding] = []

    # LLM-driven mismatches take priority
    llm_mismatches: list[LLMMismatchItem] = getattr(semantic_context, "llm_mismatches", [])
    for m in llm_mismatches:
        layer = LAYER_MAP.get(m.layer, MismatchLayer.REPRESENTATION)
        findings.append(MismatchFinding(
            layer=layer,
            title=m.title,
            description=m.description,
            evidence=m.evidence,
            confidence=m.confidence,
        ))

    # Heuristic fallback / supplement (only if LLM didn't produce enough)
    if len(findings) < 2:
        findings.extend(_heuristic_mismatches(surface, semantic_context))

    findings.sort(key=lambda f: f.confidence, reverse=True)
    logger.info(f"Located {len(findings)} mismatches ({len(llm_mismatches)} LLM + {len(findings) - len(llm_mismatches)} heuristic)")
    return findings


def _heuristic_mismatches(surface, semantic_context) -> list[MismatchFinding]:
    findings: list[MismatchFinding] = []
    existing_titles = set()

    auth_gate_targets = [t for t in surface.test_targets if "auth_gate_redirect" in t.blockers or "js_redirect_to_login" in t.blockers]
    login_page_targets = [t for t in surface.test_targets if "login_form_detected" in t.blockers]
    topicurl_targets = [t for t in surface.test_targets if any("topicurl=" in tag for tag in t.tags)]
    has_cgi = any("cstecgi.cgi" in ep.url for ep in surface.endpoints)
    has_topicurl_js = any(a.path.endswith("topicurl.js") for a in surface.frontend_assets)

    if auth_gate_targets:
        findings.append(MismatchFinding(
            layer=MismatchLayer.REPRESENTATION,
            title="Auth gate active: pages blocked",
            description=f"{len(auth_gate_targets)} pages redirect to login. Credential state needs recovery.",
            evidence=[t.url for t in auth_gate_targets[:5]],
            confidence=0.7,
        ))
        existing_titles.add(findings[-1].title)

    if has_topicurl_js and has_cgi and topicurl_targets:
        title = "CGI topicurl dispatching detected"
        if title not in existing_titles:
            findings.append(MismatchFinding(
                layer=MismatchLayer.TRANSFER,
                title=title,
                description=f"{len(topicurl_targets)} topicurl API targets found, all blocked by auth.",
                evidence=[f"topicurl={t.request_template.get('topicurl', '')}" for t in topicurl_targets[:6]],
                confidence=0.65,
            ))

    if not surface.config_sources:
        findings.append(MismatchFinding(
            layer=MismatchLayer.SOURCE,
            title="Missing config source",
            description="No config source discovered in rootfs",
            evidence=["config_sources=0"],
            confidence=0.5,
        ))

    if not findings:
        findings.append(MismatchFinding(
            layer=MismatchLayer.REPRESENTATION,
            title="Representation likely unresolved",
            description="Default fallback mismatch",
            evidence=["heuristic_default"],
            confidence=0.3,
        ))

    return findings
