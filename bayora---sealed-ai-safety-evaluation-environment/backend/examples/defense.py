"""
Bayora Sample Blue Team Defense Artifact
Evaluates incoming prompt and returns 'allow' or 'block'.
Executed inside sealed runner (network_mode: none, read-only rootfs, unprivileged user).
"""

def evaluate(prompt: str) -> str:
    # Whitelist / keyword tripwires
    harmful_terms = [
        "override",
        "jailbreak",
        "bypass",
        "canary",
        "debug mode",
        "disable moderation",
    ]
    prompt_lower = prompt.lower()
    for term in harmful_terms:
        if term in prompt_lower:
            return "block"
    return "allow"
