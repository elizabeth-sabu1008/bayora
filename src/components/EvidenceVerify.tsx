import React, { useState } from 'react';
import { useGateway } from '../context/GatewayContext';
import { AuditChain, AuditEvent, VerificationResult } from '../core/auditChain';
import { EvidenceManager } from '../core/evidence';
import { sha256Hex, canonicalJSON } from '../core/crypto';
import {
  ShieldCheck,
  ShieldAlert,
  Download,
  RotateCcw,
  AlertTriangle,
  CheckCircle2,
  Bug,
  FileArchive,
  Fingerprint,
  KeyRound,
  FileCode,
} from 'lucide-react';

export const EvidenceVerify: React.FC = () => {
  const { gateway, currentToken, addToast } = useGateway();

  // Verification state on real chain
  const [liveVerification, setLiveVerification] = useState<VerificationResult | null>(null);
  const [isVerifyingLive, setIsVerifyingLive] = useState<boolean>(false);
  const [isExportingZip, setIsExportingZip] = useState<boolean>(false);

  // Tamper playground state
  const [tamperedEvents, setTamperedEvents] = useState<AuditEvent[]>(() => {
    return JSON.parse(JSON.stringify(gateway.auditChain.getEvents()));
  });
  const [selectedBlockIdx, setSelectedBlockIdx] = useState<number>(() => {
    const evts = gateway.auditChain.getEvents();
    return evts.length > 1 ? 1 : 0;
  });
  const [tamperField, setTamperField] = useState<'status' | 'actor' | 'type' | 'payload' | 'prev_hash'>('status');
  const [tamperValue, setTamperValue] = useState<string>('403');
  const [tamperedVerification, setTamperedVerification] = useState<VerificationResult | null>(null);

  const realEvents = gateway.auditChain.getEvents();
  const checkpoints = gateway.auditChain.getCheckpoints();

  // Run live verification
  const handleVerifyLive = async () => {
    setIsVerifyingLive(true);
    try {
      const res = await AuditChain.verify(realEvents, checkpoints, gateway.gatewayPublicKeyHex);
      setLiveVerification(res);
      addToast({
        type: res.valid ? 'success' : 'error',
        title: res.valid ? 'Proof Soundness Verified ✓' : 'Chain Invalid',
        message: res.details || res.errorMessage || 'Verification finished.',
      });
    } catch (e: any) {
      addToast({ type: 'error', title: 'Verification Error', message: e.message });
    } finally {
      setIsVerifyingLive(false);
    }
  };

  // Reset tampered copy from live chain
  const handleResetCopy = () => {
    const fresh = JSON.parse(JSON.stringify(gateway.auditChain.getEvents()));
    setTamperedEvents(fresh);
    setTamperedVerification(null);
    addToast({
      type: 'info',
      title: 'Playground Reset',
      message: 'Restored pristine copy of audit chain from live memory.',
    });
  };

  // Apply tamper to cloned chain
  const handleApplyTamper = () => {
    const copy: AuditEvent[] = JSON.parse(JSON.stringify(tamperedEvents));
    if (copy.length === 0 || selectedBlockIdx >= copy.length) return;

    const target = copy[selectedBlockIdx];

    if (tamperField === 'status') {
      target.status = Number(tamperValue) || 403;
    } else if (tamperField === 'actor') {
      target.actor = tamperValue as any;
    } else if (tamperField === 'type') {
      target.type = tamperValue;
    } else if (tamperField === 'prev_hash') {
      target.prev_hash = 'deadbeef' + target.prev_hash.slice(8);
    } else if (tamperField === 'payload') {
      try {
        target.payload = { ...target.payload, injected_tamper_flag: tamperValue };
      } catch (e) {
        target.payload = { modified: tamperValue };
      }
    }

    setTamperedEvents(copy);
    addToast({
      type: 'warning',
      title: `Tampered Block #${selectedBlockIdx}`,
      message: `Modified field '${tamperField}' to '${tamperValue}'. Now run verification to test tamper detection!`,
    });
  };

  // Run verification on tampered copy
  const handleVerifyTamperedCopy = async () => {
    const res = await AuditChain.verify(tamperedEvents, checkpoints, gateway.gatewayPublicKeyHex);
    setTamperedVerification(res);
  };

  // Download evidence pack zip
  const handleDownloadEvidenceZip = async () => {
    setIsExportingZip(true);
    try {
      const zipBlob = await EvidenceManager.generateEvidenceZip(gateway);
      EvidenceManager.triggerDownload(
        zipBlob,
        `bayora_evidence_${gateway.stateMachine.getState().toLowerCase()}.zip`
      );
      addToast({
        type: 'success',
        title: 'Evidence Pack Exported',
        message: 'Saved evidence.zip with real SHA-256 manifest and Ed25519 signatures.',
      });
    } catch (e: any) {
      addToast({ type: 'error', title: 'Export Failed', message: e.message });
    } finally {
      setIsExportingZip(false);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16 font-mono text-xs">
      {/* Top Banner */}
      <div className="bg-zinc-900/80 rounded-xl p-5 border border-zinc-800 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
            <ShieldCheck className="h-4 w-4" />
            <span>CRYPTOGRAPHIC VERIFICATION & EVIDENCE EXPORT</span>
          </div>
          <p className="text-zinc-400 font-sans mt-1">
            Prove safety testing integrity mathematically without trusting BAYORA or any participant.
            Recomputes every SHA-256 block hash, canonical serialization, and Ed25519 root signature.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            disabled={isVerifyingLive}
            onClick={handleVerifyLive}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold transition-all shadow-md shadow-emerald-950 disabled:opacity-40"
          >
            <CheckCircle2 className="h-4 w-4" />
            <span>{isVerifyingLive ? 'Verifying...' : 'Run Live Verification'}</span>
          </button>

          <button
            disabled={isExportingZip}
            onClick={handleDownloadEvidenceZip}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-100 font-bold border border-zinc-700 transition-all disabled:opacity-40"
          >
            <Download className="h-4 w-4 text-emerald-400" />
            <span>{isExportingZip ? 'Generating Zip...' : 'Download evidence.zip'}</span>
          </button>
        </div>
      </div>

      {/* Live Verification Result Box */}
      {liveVerification && (
        <div className={`p-4 rounded-xl border space-y-2 ${
          liveVerification.valid
            ? 'bg-emerald-950/30 border-emerald-500/60 text-emerald-200'
            : 'bg-rose-950/30 border-rose-500/60 text-rose-200'
        }`}>
          <div className="flex items-center gap-2 font-bold text-sm">
            {liveVerification.valid ? (
              <>
                <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                <span>LIVE LEDGER AUDIT PASSED — 100% MATHEMATICAL INTEGRITY</span>
              </>
            ) : (
              <>
                <AlertTriangle className="h-5 w-5 text-rose-400" />
                <span>INTEGRITY ERROR DETECTED ON LIVE CHAIN</span>
              </>
            )}
          </div>
          <div className="text-xs text-zinc-300 space-y-1">
            <div>Verified {liveVerification.eventsCount} sequential blocks from Genesis prev_hash (64 zeros).</div>
            <div>Verified {liveVerification.checkpointsCount} Ed25519 checkpoints against Root Public Key: <code className="text-emerald-400">{gateway.gatewayPublicKeyHex.slice(0, 16)}...</code></div>
            <div>Status: {liveVerification.details || liveVerification.errorMessage}</div>
          </div>
        </div>
      )}

      {/* Tamper With A Copy Interactive Playground */}
      <div className="bg-zinc-900/90 rounded-xl border border-zinc-800 p-5 space-y-4 shadow-xl">
        <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-zinc-800">
          <div>
            <div className="flex items-center gap-2 text-amber-400 font-bold text-sm">
              <Bug className="h-4 w-4" />
              <span>TAMPER PLAYGROUND — BREAK A COPY OF THE CHAIN</span>
            </div>
            <p className="text-zinc-400 font-sans text-xs mt-0.5">
              Edit any field of any event in an isolated copy of the audit chain. See how our verifier pinpoints the exact broken block and mismatched hash.
            </p>
          </div>

          <button
            onClick={handleResetCopy}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs transition-colors"
          >
            <RotateCcw className="h-3.5 w-3.5" />
            <span>Reset Playground Copy</span>
          </button>
        </div>

        {/* Tamper Control Panel */}
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 bg-zinc-950/70 p-4 rounded-lg border border-zinc-800">
          <div>
            <span className="text-zinc-500 text-[11px] block mb-1">Target Block Index:</span>
            <select
              value={selectedBlockIdx}
              onChange={(e) => setSelectedBlockIdx(Number(e.target.value))}
              className="w-full bg-zinc-900 border border-zinc-700 rounded px-2.5 py-1.5 text-zinc-200"
            >
              {tamperedEvents.map((evt, idx) => (
                <option key={idx} value={idx}>
                  Block #{idx} ({evt.type})
                </option>
              ))}
            </select>
          </div>

          <div>
            <span className="text-zinc-500 text-[11px] block mb-1">Field to Tamper:</span>
            <select
              value={tamperField}
              onChange={(e) => setTamperField(e.target.value as any)}
              className="w-full bg-zinc-900 border border-zinc-700 rounded px-2.5 py-1.5 text-zinc-200"
            >
              <option value="status">status (e.g. 200 ➔ 403)</option>
              <option value="actor">actor (e.g. Red ➔ Admin)</option>
              <option value="type">type (e.g. inject action)</option>
              <option value="prev_hash">prev_hash (break chain link)</option>
              <option value="payload">payload (inject secret data)</option>
            </select>
          </div>

          <div>
            <span className="text-zinc-500 text-[11px] block mb-1">New Tampered Value:</span>
            <input
              type="text"
              value={tamperValue}
              onChange={(e) => setTamperValue(e.target.value)}
              placeholder="e.g. 403 or MaliciousActor"
              className="w-full bg-zinc-900 border border-zinc-700 rounded px-2.5 py-1.5 text-zinc-200"
            />
          </div>

          <div className="flex items-end gap-2">
            <button
              onClick={handleApplyTamper}
              className="flex-1 px-3 py-2 rounded bg-amber-600/30 hover:bg-amber-600/50 text-amber-200 border border-amber-500/50 font-bold transition-all"
            >
              1. Mutate Block
            </button>
            <button
              onClick={handleVerifyTamperedCopy}
              className="flex-1 px-3 py-2 rounded bg-rose-600 hover:bg-rose-500 text-white font-bold transition-all shadow-md shadow-rose-950"
            >
              2. Run Verifier
            </button>
          </div>
        </div>

        {/* Tamper Verification Feedback */}
        {tamperedVerification && (
          <div className={`p-4 rounded-xl border space-y-3 ${
            tamperedVerification.valid
              ? 'bg-emerald-950/30 border-emerald-500/50 text-emerald-200'
              : 'bg-rose-950/40 border-rose-500/60 text-rose-200'
          }`}>
            <div className="flex items-center gap-2 font-bold text-sm">
              {tamperedVerification.valid ? (
                <>
                  <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                  <span>Chain copy is still valid (No tamper applied yet)</span>
                </>
              ) : (
                <>
                  <ShieldAlert className="h-5 w-5 text-rose-400" />
                  <span>TAMPERING DETECTED BY CRYPTOGRAPHIC PROOF!</span>
                </>
              )}
            </div>

            {!tamperedVerification.valid && (
              <div className="space-y-2 text-xs">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 bg-zinc-950/80 p-3 rounded-lg border border-rose-900/50">
                  <div>
                    <span className="text-zinc-500 text-[11px]">Broken Block Index:</span>
                    <div className="text-base font-bold text-rose-400">Block #{tamperedVerification.brokenIndex}</div>
                  </div>
                  <div>
                    <span className="text-zinc-500 text-[11px]">Failed Assertion Field:</span>
                    <div className="text-base font-bold text-amber-400">{tamperedVerification.brokenField}</div>
                  </div>
                </div>

                <div className="bg-zinc-950/80 p-3 rounded-lg border border-rose-900/50 space-y-1 text-[11px]">
                  <div>
                    <span className="text-zinc-500">Expected (Recomputed) Hash:</span>
                    <div className="text-emerald-400 break-all">{tamperedVerification.expected}</div>
                  </div>
                  <div>
                    <span className="text-zinc-500">Actual Stored Tampered Hash:</span>
                    <div className="text-rose-400 break-all">{tamperedVerification.actual}</div>
                  </div>
                  <div className="text-zinc-400 pt-1 italic">
                    Reason: {tamperedVerification.errorMessage}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Checkpoints & Public Key Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Checkpoints List */}
        <div className="bg-zinc-900/90 rounded-xl border border-zinc-800 p-5 space-y-3 shadow-xl">
          <div className="flex items-center gap-2 text-sky-400 font-bold text-xs">
            <KeyRound className="h-4 w-4" />
            <span>ED25519 SIGNED CHECKPOINTS ({checkpoints.length})</span>
          </div>
          <p className="text-zinc-400 font-sans text-xs">
            Root checkpoints are signed at LOCK and SEAL to anchor state transitions permanently.
          </p>

          <div className="space-y-2.5 max-h-64 overflow-y-auto">
            {checkpoints.length === 0 ? (
              <div className="text-zinc-500 p-4 text-center bg-zinc-950/40 rounded border border-zinc-800">
                No checkpoints created yet. Advance to LOCK or SEAL phase in the Round Wizard.
              </div>
            ) : (
              checkpoints.map(cp => (
                <div key={cp.checkpointIndex} className="bg-zinc-950/70 p-3 rounded-lg border border-zinc-800 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-zinc-200">Checkpoint #{cp.checkpointIndex} ({cp.phase})</span>
                    <span className="text-emerald-400 text-[10px] font-bold px-1.5 py-0.5 rounded bg-emerald-950/60 border border-emerald-800">
                      RFC 8032 SIGNED
                    </span>
                  </div>
                  <div className="text-[11px] text-zinc-400">
                    <div>Chain Head Hash: <span className="text-zinc-300 font-bold">{cp.chainHeadHash.slice(0, 16)}...</span></div>
                    <div>Events Count: {cp.eventCount}</div>
                    <div className="truncate">Signature: <span className="text-sky-300">{cp.signature.slice(0, 32)}...</span></div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Evidence Bundle Manifest Preview */}
        <div className="bg-zinc-900/90 rounded-xl border border-zinc-800 p-5 space-y-3 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 text-emerald-400 font-bold text-xs">
              <FileArchive className="h-4 w-4" />
              <span>EVIDENCE.ZIP CONTENT MANIFEST</span>
            </div>
            <p className="text-zinc-400 font-sans text-xs mt-0.5">
              Self-contained evidence bundle for off-chain auditors and regulators:
            </p>

            <div className="mt-3 divide-y divide-zinc-800 text-[11px]">
              <div className="py-1.5 flex items-center justify-between">
                <span className="text-zinc-200 font-semibold">manifest.json</span>
                <span className="text-zinc-500">SHA-256 hashes of all zip members</span>
              </div>
              <div className="py-1.5 flex items-center justify-between">
                <span className="text-zinc-200 font-semibold">events.json</span>
                <span className="text-zinc-500">Full audit chain with genesis linkage</span>
              </div>
              <div className="py-1.5 flex items-center justify-between">
                <span className="text-zinc-200 font-semibold">commitments.json</span>
                <span className="text-zinc-500">Red and Blue H = SHA256(content + nonce)</span>
              </div>
              <div className="py-1.5 flex items-center justify-between">
                <span className="text-zinc-200 font-semibold">checkpoints.json</span>
                <span className="text-zinc-500">Ed25519 root signed checkpoints</span>
              </div>
              <div className="py-1.5 flex items-center justify-between">
                <span className="text-zinc-200 font-semibold">public_key.txt</span>
                <span className="text-zinc-500">Gateway Ed25519 verification key</span>
              </div>
              <div className="py-1.5 flex items-center justify-between">
                <span className="text-zinc-200 font-semibold">policy.json</span>
                <span className="text-zinc-500">Declarative ABAC rules matrix</span>
              </div>
              <div className="py-1.5 flex items-center justify-between">
                <span className="text-zinc-200 font-semibold">results.json</span>
                <span className="text-zinc-500">Verdict metrics & canary analysis</span>
              </div>
            </div>
          </div>

          <button
            disabled={isExportingZip}
            onClick={handleDownloadEvidenceZip}
            className="w-full mt-3 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold transition-all flex items-center justify-center gap-2"
          >
            <Download className="h-4 w-4" />
            <span>Download Certified Evidence Pack</span>
          </button>
        </div>
      </div>
    </div>
  );
};
