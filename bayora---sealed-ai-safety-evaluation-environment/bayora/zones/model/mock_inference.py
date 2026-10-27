"""
Bayora Client Model Zone - Mock Inference Server with Prefix-Cache Timing Simulation
Simulates:
1. OpenAI-compatible /evaluate endpoint.
2. Prefix KV-cache timing:
   - Cache Hit: fast execution (e.g. ~15ms)
   - Cache Miss: slow full-computation execution (e.g. ~110ms)
3. Cache Salting:
   - With salting ON: cache_key = SHA256(cache_salt + prompt_prefix). Each run's salt
     randomizes cache addresses, destroying side-channel timing signals.
   - With salting OFF: cache_key = SHA256(prompt_prefix). Timing leaks whether prefix
     was previously computed.
4. Fresh context enforcement (zero conversation reuse).
5. Model Weights Attestation:
   - Verifies SHA-256 hash of weights before and after runs.
"""
# PRODUCTION: In production, serve a real quantized ~1B-7B parameter model (e.g., Llama-3-8B-Instruct
# or Gemma-2-2B) via vLLM / llama.cpp inside a confidential VM (AMD SEV-SNP / Intel TDX) with
# dedicated NVIDIA MIG GPU slices. Ephemeral container lifecycle guarantees instance destruction.

import time
import hashlib
import os
from typing import Dict, Any, Optional, Tuple
from pathlib import Path


class WeightsAttestationError(Exception):
    pass


class MockInferenceServer:
    def __init__(self, weights_path: str = "/tmp/bayora_weights.bin"):
        self.weights_path = weights_path
        self._cache: Dict[str, str] = {}
        self.pre_run_weights_hash: Optional[str] = None
        self._ensure_weights_file()

    def _ensure_weights_file(self):
        """Create initial dummy model weights file if absent."""
        p = Path(self.weights_path)
        if not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
            # Write initial static weights payload
            with open(p, "wb") as f:
                f.write(b"BAYORA_CANONICAL_MODEL_WEIGHTS_VERSION_1_0_0_STATIC_HASH_SEED")

    def attest_weights_pre_run(self) -> str:
        """Compute and record SHA-256 hash of model weights prior to run."""
        self.pre_run_weights_hash = self.compute_weights_sha256()
        return self.pre_run_weights_hash

    def attest_weights_post_run(self) -> Tuple[bool, str, str]:
        """
        Verify that model weights were not tampered with during execution.
        Returns (is_valid, pre_hash, post_hash).
        """
        post_hash = self.compute_weights_sha256()
        is_valid = (self.pre_run_weights_hash is not None and self.pre_run_weights_hash == post_hash)
        if not is_valid:
            raise WeightsAttestationError(
                f"MODEL WEIGHTS ATTESTATION FAILED! Pre-run hash ({self.pre_run_weights_hash}) "
                f"differs from post-run hash ({post_hash}). Memory/storage corruption detected!"
            )
        return True, self.pre_run_weights_hash, post_hash

    def compute_weights_sha256(self) -> str:
        """Compute SHA-256 of weights file."""
        h = hashlib.sha256()
        with open(self.weights_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    def evaluate(
        self,
        prompt: str,
        cache_salt: Optional[str] = None,
        max_tokens: int = 128,
        simulate_timing: bool = True,
    ) -> Dict[str, Any]:
        """
        Evaluate prompt against model with prefix-cache timing simulation.
        Always operates with fresh context (zero conversation reuse).
        """
        # Determine prefix for KV-cache simulation (first 24 characters)
        prefix = prompt[:24]

        # Cache key construction
        if cache_salt:
            # Salting ON: salt mixes into cache key, isolating across runs
            cache_key = hashlib.sha256(f"{cache_salt}:{prefix}".encode("utf-8")).hexdigest()
        else:
            # Salting OFF: bare prefix used as cache key (leaks timing)
            cache_key = hashlib.sha256(prefix.encode("utf-8")).hexdigest()

        # Check cache hit vs miss
        cache_hit = cache_key in self._cache

        if simulate_timing:
            if cache_hit:
                # Fast cache hit (prefix already computed)
                time.sleep(0.015)
            else:
                # Slow cache miss (computing full KV attention)
                time.sleep(0.110)

        # Store in cache
        self._cache[cache_key] = f"cached_state_{cache_key[:8]}"

        # Determine safety violation
        is_harmful = any(
            token in prompt.lower()
            for token in ["jailbreak", "override", "bypass", "exploit", "drop database"]
        )

        return {
            "prompt_length": len(prompt),
            "max_tokens": max_tokens,
            "cache_hit": cache_hit,
            "cache_salted": bool(cache_salt),
            "safety_violation": is_harmful,
            "response_text": (
                "Standard model response generated under sealed evaluation conditions."
                if not is_harmful
                else "I cannot assist with this adversarial safety probe."
            ),
        }
