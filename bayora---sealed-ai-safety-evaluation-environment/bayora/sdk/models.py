"""
Bayora Test & Campaign Definitions (YAML schema validation)
Provides friendly, actionable error messages for developers and testers.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator, ValidationError
import yaml


class AttackItem(BaseModel):
    name: str = Field(..., description="Descriptive identifier for this adversarial prompt")
    prompt: str = Field(..., description="Adversarial input text to evaluate")
    category: Optional[str] = Field("jailbreak", description="Threat category (e.g. jailbreak, extraction, injection)")
    expected_verdict: Optional[str] = Field("blocked", description="Expected coarse oracle verdict: blocked | passed")

    @field_validator("prompt")
    @classmethod
    def validate_prompt_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError(
                "Attack prompt cannot be empty. "
                "Fix: Provide an adversarial input string in the 'prompt' field of attacks.yaml."
            )
        return v.strip()


class AttacksFile(BaseModel):
    version: str = Field("1.0", description="Schema version")
    target_category: Optional[str] = Field("adversarial-robustness", description="Campaign test suite focus")
    attacks: List[AttackItem] = Field(..., min_length=1, description="List of attack test cases")

    @field_validator("attacks")
    @classmethod
    def validate_attacks_list(cls, v: List[AttackItem]) -> List[AttackItem]:
        if not v:
            raise ValueError(
                "The 'attacks' list must contain at least one attack entry. "
                "Fix: Add at least one item under 'attacks:' with 'name' and 'prompt'."
            )
        return v


class CampaignDefinition(BaseModel):
    name: str = Field(..., description="Name of the safety evaluation campaign")
    query_budget: int = Field(50, ge=1, le=1000, description="Per-round query budget (default 50)")
    deadline_seconds: float = Field(0.5, ge=0.01, le=30.0, description="Constant latency deadline (seconds)")
    defense_file: Optional[str] = Field(None, description="Path to blue defense script, e.g. defense.py")
    attacks_file: Optional[str] = Field(None, description="Path to attacks YAML, e.g. attacks.yaml")

    @classmethod
    def from_yaml(cls, yaml_content: str) -> "CampaignDefinition":
        try:
            data = yaml.safe_load(yaml_content)
            if not isinstance(data, dict):
                raise ValueError("YAML root must be a dictionary. Fix: check indentation.")
            return cls(**data)
        except ValidationError as e:
            # Build user-friendly error summary
            error_msgs = []
            for err in e.errors():
                loc = " -> ".join(str(l) for l in err["loc"])
                msg = err["msg"]
                error_msgs.append(f"  • In '{loc}': {msg}")
            raise ValueError(
                f"Invalid Bayora Campaign YAML definition:\n" + "\n".join(error_msgs) +
                "\nFix: Verify your campaign.yaml fields match required schema (name, query_budget, deadline_seconds)."
            ) from e
        except yaml.YAMLError as ye:
            raise ValueError(f"YAML Syntax Error: {str(ye)}\nFix: Check for invalid YAML syntax or tabs.") from ye
