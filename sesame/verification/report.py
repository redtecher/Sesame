def build_summary(targets, metrics, hypotheses) -> str:
    parts = [
        f"Discovered {len(targets)} targets, {metrics.reachable_pages_after} pages reachable, {metrics.fuzzable_targets_after} fuzz-ready",
    ]
    login_count = sum(1 for t in targets if "login" in str(t.blockers).lower())
    if login_count:
        parts.append(f"{login_count} auth-blocked")
    if hypotheses:
        parts.append(f"top mismatch: {hypotheses[0].title}")
    return "; ".join(parts)
