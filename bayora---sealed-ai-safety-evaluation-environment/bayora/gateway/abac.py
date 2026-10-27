import re
from typing import Dict, Any, List, Optional
import yaml
from pathlib import Path

class ABACPolicyEngine:
    def __init__(self, policy_path: str = "gateway/policy.yaml"):
        self.policy_path = policy_path
        self.rules: List[Dict[str, Any]] = []
        self.default_effect: str = "deny"
        self.load_policy()

    def load_policy(self):
        p = Path(self.policy_path)
        if not p.exists():
            # Fallback path if running from tests or gateway directory
            alt_path = Path(__file__).parent / "policy.yaml"
            if alt_path.exists():
                p = alt_path
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                self.default_effect = data.get("default_effect", "deny")
                self.rules = data.get("rules", [])
        else:
            # Fallback inline minimal policy if file missing
            self.rules = []
            self.default_effect = "deny"

    @staticmethod
    def _match_path(pattern: str, actual: str) -> bool:
        """
        Match route template like /rounds/{id}/commit/red or /rounds/* against actual path.
        """
        if pattern == "*" or pattern == actual:
            return True
        # Convert {param} to [^/]+ and * to .*
        regex_pattern = re.sub(r'\{[^}]+\}', r'[^/]+', pattern)
        regex_pattern = regex_pattern.replace('*', '.*')
        regex = f"^{regex_pattern}$"
        return bool(re.match(regex, actual))

    def evaluate(
        self,
        role: str,
        action: str,
        resource: str,
        round_state: Optional[str] = None
    ) -> bool:
        """
        Evaluate role + action + resource + round state.
        Default deny: returns True ONLY if an explicit allow rule matches.
        """
        for rule in self.rules:
            # Check role
            rule_role = rule.get("role")
            if rule_role != "*" and rule_role != role:
                continue

            # Check action
            rule_action = rule.get("action")
            if rule_action != "*" and rule_action != action:
                continue

            # Check resource path pattern
            rule_resource = rule.get("resource", "")
            if not self._match_path(rule_resource, resource):
                continue

            # Check allowed states
            allowed_states = rule.get("allowed_states", ["*"])
            if "*" not in allowed_states:
                if round_state is None or round_state not in allowed_states:
                    continue

            # If all matched
            return rule.get("effect", "deny") == "allow"

        return False
