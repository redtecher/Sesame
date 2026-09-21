import json

from sesame.domain.report import FuzzArtifact, ReachabilityLevel


def build_fuzz_artifacts(targets, hypotheses, session_state=None):
    artifacts = []
    prerequisites = [h.title for h in hypotheses[:3]]
    session_state = session_state or {}
    cookies = session_state.get("cookies", {})
    url_tokens = session_state.get("url_tokens", {})

    for target in targets:
        if target.reachability in {ReachabilityLevel.POST_AUTH_PAGE, ReachabilityLevel.API_READY, ReachabilityLevel.FUZZ_READY}:
            artifact = FuzzArtifact(
                target_url=target.url,
                request_template=_request_template_for_target(target),
                state_prerequisites=prerequisites + target.request_chain,
                seed_cookies=_seed_cookies_for_target(target, cookies),
                seed_headers={"User-Agent": "sesame-fuzz-seed", "Content-Type": "application/x-www-form-urlencoded"},
                seed_body=_seed_body_for_target(target),
                request_chain=target.request_chain,
                seed_url_tokens=dict(url_tokens) if url_tokens else {},
                url_token_pattern=";stok={stok}" if url_tokens else "",
            )
            artifacts.append(artifact)
    return artifacts


def _request_template_for_target(target):
    template = {"method": target.method, "url": target.url}
    if target.request_template:
        for k, v in target.request_template.items():
            if isinstance(v, str):
                template[k] = v
    topicurl = target.request_template.get("topicurl", "") if target.request_template else ""
    if topicurl:
        template["body"] = json.dumps({"topicurl": topicurl})
        template["content_type"] = "application/json"
    template.setdefault("cookies", "<fill-auth-cookies-if-needed>")
    template.setdefault("note", "use-SESSION_ID-cookie-from-login")
    return template


def _seed_body_for_target(target):
    topicurl = ""
    for step in target.request_chain:
        if step.startswith("topicurl="):
            topicurl = step.split("=", 1)[1]
            break
    if not topicurl:
        topicurl = (target.request_template or {}).get("topicurl", "")

    if target.url == "/cgi-bin/cstecgi.cgi" and topicurl:
        body = {"topicurl": topicurl}
        if topicurl == "login":
            body.update({"username": "admin", "password": ""})
        return body
    if target.target_type == "api":
        return {"topicurl": topicurl or "probe"}
    return {}


def _seed_cookies_for_target(target, session_cookies=None):
    if session_cookies:
        return dict(session_cookies)
    return {"SESSION_ID": "<obtain-via-login-flow>"}
