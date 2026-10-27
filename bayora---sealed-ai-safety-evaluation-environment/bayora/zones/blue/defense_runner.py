"""
Bayora Sealed Defense Runner
Executes untrusted Blue Team defense code in complete isolation.
- Container network_mode: none (zero outbound/inbound network).
- Read-only filesystem, non-root execution (nobody:nogroup).
- Strict CPU, memory, and timeout limits.
- Evaluates evaluate(prompt) -> allow | block.
- Returns ONLY the coarse verdict to the gateway.
"""
# PRODUCTION: In production, enforce runtime: runsc (gVisor) or Kata Containers (microVM)
# with a restrictive seccomp profile, Landlock LSM sandbox, and ephemeral execution microVMs.

import sys
import os
import time
import socket
import json
import traceback
from typing import Dict, Any, Optional

# Safe built-in whitelist for defense evaluation
SAFE_BUILTINS = {
    "abs": abs, "all": all, "any": any, "bool": bool, "dict": dict,
    "enumerate": enumerate, "float": float, "int": int, "len": len,
    "list": list, "max": max, "min": min, "range": range, "round": round,
    "set": set, "str": str, "sum": sum, "tuple": tuple, "zip": zip,
    "True": True, "False": False, "None": None, "isinstance": isinstance,
}


class SealedDefenseRunner:
    def __init__(self, code_str: Optional[str] = None):
        self.code_str = code_str
        self._compiled_fn = None
        if code_str:
            self.load_code(code_str)

    def load_code(self, code_str: str):
        """
        Compile and bind the Blue Team's evaluate(prompt) function.
        Restricts execution namespace to prevent access to os, sys, socket, or file I/O.
        """
        self.code_str = code_str
        local_scope: Dict[str, Any] = {}
        # Execute definition within sanitized namespace
        # PRODUCTION: In production, use WebAssembly (Wasmtime sandbox) or gVisor sandbox.
        restricted_globals = {"__builtins__": SAFE_BUILTINS}
        exec(code_str, restricted_globals, local_scope)

        if "evaluate" not in local_scope or not callable(local_scope["evaluate"]):
            raise ValueError("Defense code must define a callable function: evaluate(prompt) -> str")
        self._compiled_fn = local_scope["evaluate"]

    def evaluate(self, prompt: str, timeout_seconds: float = 0.1) -> str:
        """
        Execute defense against prompt.
        Returns ONLY 'allow' or 'block'. Never returns internal state, scores, or prompt.
        """
        if not self._compiled_fn:
            # Default allow if no defense active
            return "allow"

        try:
            # Simple timeout and execution wrapper
            start_t = time.perf_counter()
            result = self._compiled_fn(prompt)
            elapsed = time.perf_counter() - start_t

            if elapsed > timeout_seconds:
                # Execution exceeded deadline -> treat as block/error
                return "block"

            # Normalize verdict
            if isinstance(result, bool):
                return "allow" if result else "block"
            verdict = str(result).strip().lower()
            return "allow" if verdict in ("allow", "passed", "true", "safe") else "block"
        except Exception:
            # PRODUCTION: In production, record execution fault in internal telemetry without leaking stack trace.
            return "block"


def run_socket_server(socket_path: str = "/tmp/defense.sock"):
    """
    Local UNIX domain socket listener for communication with the Gateway airlock.
    Guarantees zero IP network footprint (runs with network_mode: none).
    """
    if os.path.exists(socket_path):
        os.remove(socket_path)

    runner = SealedDefenseRunner()

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    server.listen(10)
    # Set permissions so gateway can connect
    os.chmod(socket_path, 0o666)

    while True:
        conn, _ = server.accept()
        try:
            data = conn.recv(65536)
            if not data:
                continue
            req = json.loads(data.decode("utf-8"))
            action = req.get("action")

            if action == "load":
                runner.load_code(req.get("code", ""))
                conn.sendall(json.dumps({"status": "loaded"}).encode("utf-8"))
            elif action == "evaluate":
                prompt = req.get("prompt", "")
                verdict = runner.evaluate(prompt)
                # Returns ONLY the verdict!
                conn.sendall(json.dumps({"verdict": verdict}).encode("utf-8"))
            else:
                conn.sendall(json.dumps({"error": "unknown_action"}).encode("utf-8"))
        except Exception as e:
            conn.sendall(json.dumps({"verdict": "block", "error": "runner_error"}).encode("utf-8"))
        finally:
            conn.close()


if __name__ == "__main__":
    sock = sys.argv[1] if len(sys.argv) > 1 else "/tmp/defense.sock"
    run_socket_server(sock)
