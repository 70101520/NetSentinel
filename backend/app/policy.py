from datetime import datetime, timezone
from app.models import Policy, PolicyRule
def domain_matches(domain: str, pattern: str) -> bool:
    domain=domain.rstrip(".").lower().encode("idna").decode()
    pattern=pattern.rstrip(".").lower().encode("idna").decode()
    if pattern.startswith("*."):
        suffix=pattern[2:]
        return domain.endswith("."+suffix)
    return domain==pattern
def evaluate(policy: Policy, rules: list[PolicyRule], domain: str):
    now=datetime.now(timezone.utc)
    active=(r for r in rules if r.enabled and (r.expires_at is None or r.expires_at>now))
    for rule in sorted(active,key=lambda r:r.priority):
        if domain_matches(domain,rule.domain_pattern): return rule.action,rule.id,"matched_rule"
    return policy.default_action,None,"default_policy"
