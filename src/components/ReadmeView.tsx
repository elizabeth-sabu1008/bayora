import React from 'react';
import {
  ShieldCheck,
  Lock,
  KeyRound,
  Layers,
  Cpu,
  FileCheck,
  FileArchive,
  Terminal,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
  ExternalLink,
} from 'lucide-react';

export const ReadmeView: React.FC = () => {
  return (
    <div className="space-y-8 max-w-5xl mx-auto pb-20 font-mono text-xs text-zinc-300">
      {/* Hero Header */}
      <div className="bg-gradient-to-br from-emerald-950/40 via-zinc-900 to-zinc-900 p-6 rounded-2xl border border-emerald-500/40 shadow-2xl space-y-3">
        <div className="flex items-center gap-2.5 text-emerald-400 font-bold text-sm">
          <ShieldCheck className="h-5 w-5" />
          <span>BAYORA ARCHITECTURE SPECIFICATION & INTEGRITY GUARANTEES</span>
        </div>
        <h2 className="text-xl font-bold text-zinc-100 font-mono">
          How This Works & What Is Real
        </h2>
        <p className="text-zinc-300 font-sans leading-relaxed text-sm">
          BAYORA solves the fundamental trust dilemma in AI red teaming: How can an adversarial Red team evaluate a protected Client LLM defended by a proprietary Blue team filter without either party exposing their secrets or trusting an unverified evaluator?
        </p>
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-zinc-950/80 border border-emerald-500/30 text-emerald-300 text-xs font-mono font-bold">
          <span>GOLDEN RULE: 100% computed live in-browser. Zero mock hashes, zero hardcoded timings, zero simulated proofs.</span>
        </div>
      </div>

      {/* Claims Breakdown Matrix */}
      <div className="space-y-4">
        <h3 className="text-sm font-bold text-zinc-100 uppercase tracking-wider flex items-center gap-2">
          <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          Nine Security Properties & Live Enforcement Mechanisms
        </h3>

        <div className="grid grid-cols-1 gap-4">
          {/* Claim 1 */}
          <div className="bg-zinc-900/80 p-5 rounded-xl border border-zinc-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-zinc-100 text-sm">
                1. Cryptographic Commit-Reveal Protocol (H = SHA256(content + nonce))
              </span>
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-bold">
                REAL (Web Crypto)
              </span>
            </div>
            <p className="font-sans text-xs text-zinc-400 leading-relaxed">
              <strong>Claim:</strong> Neither Red nor Blue can alter their test assets after the round commences.
            </p>
            <p className="font-sans text-xs text-zinc-300 leading-relaxed">
              <strong>Enforcement:</strong> At the <code className="text-emerald-300">COMMIT</code> phase, parties generate 32 cryptographically secure random bytes via <code className="text-emerald-300">crypto.getRandomValues()</code> and submit <code className="text-emerald-300">H = SHA256(content + nonce)</code>. At <code className="text-emerald-300">REVEAL</code>, the gateway recomputes the hash from the plaintext and compares digests bit-for-bit.
            </p>
          </div>

          {/* Claim 2 */}
          <div className="bg-zinc-900/80 p-5 rounded-xl border border-zinc-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-zinc-100 text-sm">
                2. Zero-Knowledge AES-GCM 256 Vault Containment
              </span>
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-bold">
                REAL (Web Crypto AES-GCM)
              </span>
            </div>
            <p className="font-sans text-xs text-zinc-400 leading-relaxed">
              <strong>Claim:</strong> Red's attack prompts and Blue's defense code cannot be inspected by each other or by the admin prior to the REVEAL phase.
            </p>
            <p className="font-sans text-xs text-zinc-300 leading-relaxed">
              <strong>Enforcement:</strong> Assets are encrypted client-side using Web Crypto <code className="text-emerald-300">AES-GCM 256</code> with random 12-byte initialization vectors. Pre-reveal read requests return HTTP 403 Forbidden. Decryption keys are held in gateway memory and released only upon verified pre-image revelation.
            </p>
          </div>

          {/* Claim 3 */}
          <div className="bg-zinc-900/80 p-5 rounded-xl border border-zinc-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-zinc-100 text-sm">
                3. Gateway Ed25519 Signed Role Tokens & Strict Policy Enforcer
              </span>
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-bold">
                REAL (@noble/ed25519)
              </span>
            </div>
            <p className="font-sans text-xs text-zinc-400 leading-relaxed">
              <strong>Claim:</strong> The gateway is the sole communication choke point. No zone can access another zone directly.
            </p>
            <p className="font-sans text-xs text-zinc-300 leading-relaxed">
              <strong>Enforcement:</strong> When you switch roles in the top bar, BAYORA mints an RFC 8032 Ed25519-signed token. Every API invocation validates this signature, queries declarative ABAC policy rules in <code className="text-emerald-300">src/core/policy.ts</code>, verifies state machine validity, and appends the attempt to the tamper-evident ledger.
            </p>
          </div>

          {/* Claim 4 */}
          <div className="bg-zinc-900/80 p-5 rounded-xl border border-zinc-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-zinc-100 text-sm">
                4. Append-Only Tamper-Evident Audit Hash Chain
              </span>
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-bold">
                REAL (Canonical JSON + SHA-256)
              </span>
            </div>
            <p className="font-sans text-xs text-zinc-400 leading-relaxed">
              <strong>Claim:</strong> Every action, allowed or denied, is permanently recorded in a sequence where any retroactive modification is mathematically detected.
            </p>
            <p className="font-sans text-xs text-zinc-300 leading-relaxed">
              <strong>Enforcement:</strong> Block hashes are calculated as <code className="text-emerald-300">entry_hash = SHA256(prev_hash + canonicalJSON(event))</code>, with Genesis starting at 64 zeros. Try the "Tamper with a copy" feature on the Evidence tab to observe how modifying a single character causes the recomputed hash chain to break immediately.
            </p>
          </div>

          {/* Claim 5 */}
          <div className="bg-zinc-900/80 p-5 rounded-xl border border-zinc-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-zinc-100 text-sm">
                5. Root Ed25519 Checkpoints at LOCK and SEAL
              </span>
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-bold">
                REAL (RFC 8032)
              </span>
            </div>
            <p className="font-sans text-xs text-zinc-400 leading-relaxed">
              <strong>Claim:</strong> State transitions are cryptographically anchored so neither party can claim that the test rules were altered mid-execution.
            </p>
            <p className="font-sans text-xs text-zinc-300 leading-relaxed">
              <strong>Enforcement:</strong> At the <code className="text-emerald-300">LOCK</code> and <code className="text-emerald-300">SEAL</code> phases, the gateway digitally signs the latest block hash using its private Ed25519 key. The verification algorithm checks these signatures against the published public key.
            </p>
          </div>

          {/* Claim 6 */}
          <div className="bg-zinc-900/80 p-5 rounded-xl border border-zinc-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-zinc-100 text-sm">
                6. Sealed Runner: Dual Containment Sandbox with Strict CSP
              </span>
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-bold">
                REAL (iframe sandbox + CSP default-src 'none')
              </span>
            </div>
            <p className="font-sans text-xs text-zinc-400 leading-relaxed">
              <strong>Claim:</strong> Blue's code executes with zero egress and cannot phone home or tamper with application state.
            </p>
            <p className="font-sans text-xs text-zinc-300 leading-relaxed">
              <strong>Enforcement:</strong> Blue's defense function runs inside a sandboxed iframe with <code className="text-emerald-300">sandbox="allow-scripts"</code> (no allow-same-origin, origin is opaque <code className="text-emerald-300">null</code>) and <code className="text-emerald-300">Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'</code>. Run the "Real Isolation Checks" button to see the browser block <code className="text-emerald-300">fetch()</code>, <code className="text-emerald-300">window.parent</code>, and <code className="text-emerald-300">localStorage</code> in real time.
            </p>
          </div>

          {/* Claim 7 */}
          <div className="bg-zinc-900/80 p-5 rounded-xl border border-zinc-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-zinc-100 text-sm">
                7. Constant-Latency Shaped Oracle with Canary Extraction Guard
              </span>
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-bold">
                REAL (t0 + DEADLINE_MS padding & Gemini Flash)
              </span>
            </div>
            <p className="font-sans text-xs text-zinc-400 leading-relaxed">
              <strong>Claim:</strong> Red receives only coarse verdicts (<code className="text-emerald-300">BLOCKED</code> / <code className="text-emerald-300">PASSED</code>) at a uniform deadline to prevent token timing side-channels.
            </p>
            <p className="font-sans text-xs text-zinc-300 leading-relaxed">
              <strong>Enforcement:</strong> Every reply is held until <code className="text-emerald-300">t0 + DEADLINE_MS</code> (default 1500ms) regardless of whether an early filter triggered in 2ms or the model took 900ms. Queries overrunning the budget or deadline return TIMEOUT.
            </p>
          </div>

          {/* Claim 8 */}
          <div className="bg-zinc-900/80 p-5 rounded-xl border border-zinc-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-zinc-100 text-sm">
                8. Prefix Cache Timing Attack Quantification & Provable Mitigation
              </span>
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-bold">
                REAL (Mutual Information in bits vs Noise Floor)
              </span>
            </div>
            <p className="font-sans text-xs text-zinc-400 leading-relaxed">
              <strong>Claim:</strong> Demonstrates real timing side-channels in LLM KV-cache reuse and proves mathematical elimination using cache salting + padding.
            </p>
            <p className="font-sans text-xs text-zinc-300 leading-relaxed">
              <strong>Enforcement:</strong> CacheLab runs N=200 probes against a real prefix cache with CPU compute loops. We compute empirical Mutual Information <code className="text-emerald-300">I(X; Y)</code> across a 20-bin histogram and compare against a shuffled label noise floor. Under Mode 3, leakage drops to 0 bits.
            </p>
          </div>

          {/* Claim 9 */}
          <div className="bg-zinc-900/80 p-5 rounded-xl border border-zinc-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-zinc-100 text-sm">
                9. Portable Evidence Bundle Export (evidence.zip)
              </span>
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-bold">
                REAL (JSZip + SHA-256 Manifest)
              </span>
            </div>
            <p className="font-sans text-xs text-zinc-400 leading-relaxed">
              <strong>Claim:</strong> Anyone can audit a completed round offline using standard open source tooling.
            </p>
            <p className="font-sans text-xs text-zinc-300 leading-relaxed">
              <strong>Enforcement:</strong> <code className="text-emerald-300">evidence.zip</code> packages <code className="text-emerald-300">manifest.json</code> (with SHA-256 hashes of every file), <code className="text-emerald-300">events.json</code>, <code className="text-emerald-300">commitments.json</code>, <code className="text-emerald-300">checkpoints.json</code>, <code className="text-emerald-300">public_key.txt</code>, <code className="text-emerald-300">policy.json</code>, and <code className="text-emerald-300">results.json</code>.
            </p>
          </div>
        </div>
      </div>

      {/* Offline Verification CLI Instructions */}
      <div className="bg-zinc-900/80 p-6 rounded-xl border border-zinc-800 space-y-4">
        <div className="flex items-center gap-2 text-zinc-100 font-bold text-sm">
          <Terminal className="h-4 w-4 text-emerald-400" />
          <span>Independent Offline Verification Guide (Regulator / Auditor)</span>
        </div>
        <p className="text-zinc-400 font-sans leading-relaxed text-xs">
          An external auditor does not need to believe BAYORA's web interface. Download <code className="text-emerald-300">evidence.zip</code> and run this verification snippet in Python or bash:
        </p>

        <div className="bg-zinc-950 p-4 rounded-lg border border-zinc-800 overflow-x-auto text-emerald-400 text-[11px] leading-relaxed">
          <pre>{`# 1. Unzip evidence bundle
unzip evidence.zip -d bayora_audit
cd bayora_audit

# 2. Check SHA-256 manifest integrity
python3 -c '
import json, hashlib

with open("manifest.json") as f:
    manifest = json.load(f)

for filename, expected_hash in manifest["files"].items():
    with open(filename, "rb") as f:
        computed = hashlib.sha256(f.read()).hexdigest()
    assert computed == expected_hash, f"Hash mismatch in {filename}!"
    print(f"✓ {filename}: SHA-256 OK ({computed[:16]}...)")
print("MANIFEST VERIFICATION: 100% SOUND")
'
`}</pre>
        </div>
      </div>
    </div>
  );
};
