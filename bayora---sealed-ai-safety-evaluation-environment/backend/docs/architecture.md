# Bayora Architecture Specification

## 1. System Overview
**Bayora** is a prototype sealed testing harness designed for adversarial AI safety evaluations. In typical AI red-teaming and safety benchmarking, three distinct actors interact:
1. **Red Team (Attackers)**: Devises adversarial prompts, jailbreaks, prompt injection, and extraction exploits.
2. **Blue Team (Defenders)**: Designs guardrails, input filters, classification tripwires, and mitigation rules.
3. **Client LLM (System Under Test)**: The target foundation model being evaluated.

Without rigorous isolation and provable execution, three critical security failures occur:
- **Pre-execution Leaks**: Red learns Blue's filters and tailors evasions; or Blue peeks at Red's test cases to overfit heuristics.
- **Cross-Zone Collusion & Network Lateral Movement**: An attacker container exploits network connectivity or shared kernel space to compromise the model container or exfiltrate private weights.
- **Post-hoc Repudiation**: Parties dispute evaluation outcomes or claim prompts were altered after the test ran.

Bayora eliminates these vulnerabilities through **Layer-3/4 Network Segregation**, a **Cryptographic Commit–Reveal Protocol**, and **Strict ABAC State Enforcement**.

---

## 2. Network Topology & Segregation
Bayora establishes four distinct Docker networks:

```
                  +-----------------------------------+
                  |          Bayora Gateway           |
                  |  (Single multi-homed conduit)     |
                  +--+-----------+-----------+-----+--+
                     |           |           |     |
            [red-seg]|  [blue-seg| [model-seg|     |[audit-seg]
                     |           |           |     |
               +-----+--+  +-----+--+  +-----+--+  +-----+----+
               | Red    |  | Blue   |  | Model  |  | Evidence |
               | Zone   |  | Zone   |  | Zone   |  | Vault    |
               +--------+  +--------+  +--------+  +----------+
```

### Isolation Guarantees:
- **Red Zone (`red-seg`)**: Connected only to `gateway`. Cannot resolve DNS or route IP packets to `blue-seg`, `model-seg`, or `audit-seg`.
- **Blue Zone (`blue-seg`)**: Connected only to `gateway`. Completely segregated from `red-seg`.
- **Model Zone (`model-seg`)**: Isolated subnet. Only the Gateway proxy can dispatch evaluation payloads to it during the `EXECUTE` phase.
- **Evidence Vault (`audit-seg`)**: Stores tamper-evident cryptographic transcripts and hashes.

---

## 3. Production vs Prototype Scope (Honest Scope)

| Capability | Bayora Local Prototype (Laptop) | Production Scale Equivalent |
| :--- | :--- | :--- |
| **Compute & Runtime** | Standard Docker bridge + Linux cgroups (`docker compose up`) | **Kata Containers** (microVMs via QEMU/Cloud-Hypervisor) or **gVisor (`runsc`)** for untrusted code execution |
| **Hardware / GPU** | CPU execution stub (no GPU required) | **NVIDIA MIG (Multi-Instance GPU)** slices or hardware TEEs (AMD SEV-SNP / Intel TDX) |
| **Database** | SQLite local file with SHA-256 event chaining | Cloud SQL / PostgreSQL with append-only ledger and WORM replication |
| **Audit Logs** | Local SQLite `events` table with previous hash chaining | Public transparency log (e.g. **Sigstore / Rekor**) and HSM-signed roots |

---

## 4. Cryptographic Commit-Reveal Protocol

To guarantee that neither Red nor Blue can alter their strategies or claim results were doctored:
1. **Commitment Phase**:
   $$\text{Preimage} = \text{canonical\_json}(P) + \text{nonce}_{32\text{ bytes}}$$
   $$H = \text{SHA256}(\text{Preimage})$$
   Red and Blue send $H$ to the Gateway during the `COMMIT` state. The Gateway stores *only* the hash $H$.
2. **Lock Phase**:
   When both hashes are stored, the Gateway enters `LOCK`. Submissions are frozen.
3. **Execution Phase**:
   During `EXECUTE`, Red tests run against the model via the Gateway.
4. **Reveal & Verification Phase**:
   During `REVEAL`, both parties submit $(P, \text{nonce})$.
   The Gateway recomputes:
   $$H' = \text{SHA256}(\text{canonical\_json}(P) + \text{nonce})$$
   - If $H' == H$: Transition to `VERIFY` $\to$ `COMPLETED`.
   - If $H' \neq H$: Transition immediately to `INVALID`. Audit alarm is raised.
