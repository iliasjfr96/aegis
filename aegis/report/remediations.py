"""Remediation guidance per OWASP category (static, curated)."""

from aegis.graph.state import OwaspCategory

REMEDIATIONS = {
    OwaspCategory.LLM01_PROMPT_INJECTION: (
        "Add input-layer injection detection (classifier or heuristic), separate "
        "system instructions from user data via structured roles, and apply "
        "least-privilege on what the model can do after any instruction."
    ),
    OwaspCategory.LLM02_SENSITIVE_DISCLOSURE: (
        "Enforce document-level access control BEFORE retrieval (never put "
        "restricted docs in the same index), scrub secrets from context, and add "
        "an output filter that redacts known-sensitive patterns (canaries, PII)."
    ),
    OwaspCategory.LLM06_EXCESSIVE_AGENCY: (
        "Require human approval for side-effect tools (email, file access), "
        "restrict tools to a strict allowlist, and scope tool permissions per "
        "user role rather than globally."
    ),
    OwaspCategory.LLM07_SYSTEM_PROMPT_LEAK: (
        "Never place secrets in prompts (use a secrets manager + server-side "
        "injection), add an output scrubber for config tokens, and treat the "
        "system prompt as public-by-design."
    ),
    OwaspCategory.LLM08_VECTOR_WEAKNESS: (
        "Segment indexes by sensitivity, filter retrieved chunks by user "
        "clearance, and monitor for data-poisoning patterns in the corpus."
    ),
}

REMEDIATIONS.update({
    OwaspCategory.WEB_HEADERS: "Set CSP, HSTS, X-Content-Type-Options, X-Frame-Options and Referrer-Policy at the reverse proxy or framework level; hide server version tokens.",
    OwaspCategory.WEB_CORS: "Use a strict origin allowlist; never combine wildcard origins with credentials; reject reflected arbitrary origins.",
    OwaspCategory.WEB_EXPOSED: "Block dotfiles and build artifacts at the web server (deny /.env, /.git); move secrets to a secrets manager; rotate any leaked credentials immediately.",
    OwaspCategory.WEB_COOKIES: "Set Secure, HttpOnly and SameSite=Lax/Strict on all session cookies.",
    OwaspCategory.WEB_JWT: "Always require exp, reject alg=none, use strong random secrets (or asymmetric keys), and rotate signing keys.",
    OwaspCategory.WS_AUTH: "Require authentication during the WS handshake (token or session) before accepting any event; authorize every event server-side.",
    OwaspCategory.WS_INJECTION: "Validate message schema strictly, cap payload size, and never let one bad frame kill the connection.",
    OwaspCategory.WS_RATELIMIT: "Add per-connection rate limiting (token bucket) and disconnect abusive clients with code 1008.",
})
