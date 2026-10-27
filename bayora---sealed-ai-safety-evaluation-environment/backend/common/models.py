from enum import Enum
from typing import Any, Dict, Optional, List
try:
    from pydantic import BaseModel, Field
except ImportError:
    class BaseModel:
        def __init__(self, **data):
            for k, v in data.items():
                setattr(self, k, v)
        def dict(self):
            return self.__dict__
    def Field(default=..., **kwargs):
        return default if default is not ... else None


class RoundState(str, Enum):
    CREATED = "CREATED"
    COMMIT = "COMMIT"
    LOCK = "LOCK"
    EXECUTE = "EXECUTE"
    SEAL = "SEAL"
    REVEAL = "REVEAL"
    VERIFY = "VERIFY"
    COMPLETED = "COMPLETED"
    INVALID = "INVALID"


ALLOWED_TRANSITIONS = {
    RoundState.CREATED: RoundState.COMMIT,
    RoundState.COMMIT: RoundState.LOCK,
    RoundState.LOCK: RoundState.EXECUTE,
    RoundState.EXECUTE: RoundState.SEAL,
    RoundState.SEAL: RoundState.REVEAL,
    RoundState.REVEAL: RoundState.VERIFY,
    RoundState.VERIFY: RoundState.COMPLETED,
}


class UserRole(str, Enum):
    RED = "red"
    BLUE = "blue"
    ADMIN = "admin"
    AUDITOR = "auditor"


# --- Part 2: Coarse Verdicts & Shaped Oracle ---
class CoarseVerdict(str, Enum):
    BLOCKED = "blocked"
    PASSED = "passed"
    ERROR = "error"
    TIMEOUT = "timeout"


class ShapedOracleResponse(BaseModel):
    """
    Shaped Oracle Response for Red Team.
    Guarantees that Red receives ONLY a coarse verdict: {blocked, passed, error, timeout}.
    No raw model text, no defense scores, no reasons, no stack traces.
    """
    verdict: CoarseVerdict = Field(..., description="Coarse safety verdict: blocked, passed, error, timeout")
    round_id: str
    query_id: str


class OracleQueryRequest(BaseModel):
    prompt: str = Field(..., description="Adversarial prompt submitted to shaped oracle")
    max_tokens: Optional[int] = Field(128, description="Fixed generation cap for constant latency")


class DefenseUploadRequest(BaseModel):
    """
    Blue Team defense artifact upload.
    Contains Python code implementing `evaluate(prompt) -> allow|block`,
    along with version, metadata, and Ed25519 signature.
    """
    code: str = Field(..., description="Python source implementing evaluate(prompt)")
    version: str = Field(..., description="Semantic version string, e.g. 1.0.0")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    signature_hex: str = Field(..., description="Ed25519 signature over canonical_json(code + version)")
    public_key_hex: str = Field(..., description="Ed25519 public key in hex")


class DefenseArtifact(BaseModel):
    version: str
    code_sha256: str
    signature_hex: str
    public_key_hex: str
    verified: bool
    frozen: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class WeightsAttestation(BaseModel):
    model_name: str
    pre_sha256: str
    post_sha256: str
    verified: bool
    timestamp: str


class FindingsResponse(BaseModel):
    role: str
    round_id: str
    view_type: str
    data: Dict[str, Any]


class TokenRequest(BaseModel):
    sub: str = Field(..., description="Subject identity (e.g. red-operator-1)")
    role: UserRole = Field(..., description="Role for ABAC decisions")
    zone: str = Field(..., description="Zone location: red, blue, model, evidence, or admin")
    expires_in_seconds: int = Field(600, description="Token lifetime in seconds (default 10 min = 600s)")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    role: str
    zone: str


class CreateRoundRequest(BaseModel):
    name: str = Field(..., description="Evaluation campaign or test scenario name")
    description: Optional[str] = Field(None, description="Optional description of the test")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    round_budget: Optional[int] = Field(50, description="Per-round query budget for red team (default 50)")


class CommitSubmission(BaseModel):
    commitment_hash: str = Field(..., description="SHA-256 hash of canonical_json(content) + nonce")
    hint: Optional[str] = Field(None, description="Optional non-revealing hint/tag")


class RevealSubmission(BaseModel):
    content: Dict[str, Any] = Field(..., description="Actual payload committed earlier")
    nonce: str = Field(..., description="Original 32-byte hex nonce used during COMMIT")


class ExecuteTestRequest(BaseModel):
    test_id: str = Field(..., description="Unique test prompt / payload ID")
    input_text: str = Field(..., description="Adversarial input to evaluate against model")
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict)


class RoundResponse(BaseModel):
    id: str
    name: str
    state: RoundState
    created_at: str
    updated_at: str
    red_commit_hash: Optional[str] = None
    blue_commit_hash: Optional[str] = None
    defense_artifact_hash: Optional[str] = None
    red_revealed: bool = False
    blue_revealed: bool = False
    red_commitment_match: Optional[bool] = None
    blue_commitment_match: Optional[bool] = None
    execution_result: Optional[Dict[str, Any]] = None
    verification_status: Optional[str] = None
    error_message: Optional[str] = None
    queries_used: int = 0
    round_budget: int = 50
    model_backend: Optional[str] = None
    weights_verified: Optional[bool] = None


class StructuredEvent(BaseModel):
    id: int
    timestamp: str
    actor_sub: str
    actor_role: str
    actor_zone: str
    event_type: str
    resource: str
    action: str
    state_before: Optional[str] = None
    state_after: Optional[str] = None
    round_id: Optional[str] = None
    status_code: int
    details: Dict[str, Any] = Field(default_factory=dict)
    event_hash: str
