import React, { useState } from 'react';
import { useGateway } from '../context/GatewayContext';
import { Role, Action, Resource, ACCESS_POLICY } from '../core/policy';
import {
  ShieldAlert,
  Play,
  RotateCcw,
  CheckCircle2,
  Lock,
  Unlock,
  KeyRound,
  FileCheck,
  AlertOctagon,
  Search,
  Filter,
} from 'lucide-react';

interface MatrixTestResult {
  role: Role;
  action: Action;
  resource: Resource;
  status: number;
  message?: string;
  latencyMs: number;
}

export const AbacMatrixView: React.FC = () => {
  const { gateway, currentRole, currentToken, roundState, addToast, refreshState } = useGateway();

  const [matrixResults, setMatrixResults] = useState<MatrixTestResult[]>([]);
  const [isRunningMatrix, setIsRunningMatrix] = useState<boolean>(false);
  const [filterRole, setFilterRole] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const [vaultReadOutput, setVaultReadOutput] = useState<{
    target: string;
    status: number;
    text?: string;
    error?: string;
  } | null>(null);

  const roles: Role[] = ['Admin', 'Red', 'Blue', 'Auditor'];

  const testActions: Array<{ action: Action; resource: Resource }> = [
    { action: 'transition_state', resource: 'round_state' },
    { action: 'submit_commitment', resource: 'red_commitment' },
    { action: 'submit_commitment', resource: 'blue_commitment' },
    { action: 'store_vault_payload', resource: 'red_vault_attack_set' },
    { action: 'store_vault_payload', resource: 'blue_vault_defense_code' },
    { action: 'read_vault_payload', resource: 'red_vault_attack_set' },
    { action: 'read_vault_payload', resource: 'blue_vault_defense_code' },
    { action: 'query_oracle', resource: 'oracle_endpoint' },
    { action: 'reveal_commitment', resource: 'red_commitment' },
    { action: 'reveal_commitment', resource: 'blue_commitment' },
    { action: 'verify_audit_chain', resource: 'audit_ledger' },
    { action: 'read_audit_chain', resource: 'audit_ledger' },
    { action: 'export_evidence', resource: 'evidence_pack' },
    { action: 'run_sandbox_isolation', resource: 'sandbox_environment' },
  ];

  const runDenyMatrix = async () => {
    setIsRunningMatrix(true);
    const results: MatrixTestResult[] = [];

    // Pre-issue role tokens for each of the 4 roles
    const tokens: Record<Role, string> = {
      Admin: await gateway.issueRoleToken('Admin'),
      Red: await gateway.issueRoleToken('Red'),
      Blue: await gateway.issueRoleToken('Blue'),
      Auditor: await gateway.issueRoleToken('Auditor'),
    };

    for (const r of roles) {
      const token = tokens[r];
      for (const pair of testActions) {
        const t0 = performance.now();
        // Invoke real gateway
        const res = await gateway.invoke(token, pair.action, pair.resource, {
          testProbe: true,
          prompt: 'probe',
          content: 'probe',
          nonceHex: '00'.repeat(32),
          commitmentHash: '00'.repeat(32),
          plaintext: 'probe',
        });
        const latencyMs = Math.round((performance.now() - t0) * 10) / 10;

        results.push({
          role: r,
          action: pair.action,
          resource: pair.resource,
          status: res.status,
          message: res.error || (res.status === 200 ? 'Authorized (200 OK)' : undefined),
          latencyMs,
        });
      }
    }

    setMatrixResults(results);
    setIsRunningMatrix(false);
    refreshState();
    addToast({
      type: 'success',
      title: 'Deny Matrix Complete',
      message: `Executed ${results.length} live authorization probes across 4 roles against real gateway policy.`,
    });
  };

  const handleTestVaultRead = async (target: 'red_vault_attack_set' | 'blue_vault_defense_code') => {
    try {
      const res = await gateway.invoke(currentToken, 'read_vault_payload', target);
      if (res.status === 200) {
        setVaultReadOutput({
          target,
          status: 200,
          text: typeof res.data?.plaintext === 'string' ? res.data.plaintext.slice(0, 140) + '...' : JSON.stringify(res.data),
        });
        addToast({
          type: 'success',
          title: 'Decryption Allowed (200 OK)',
          message: `Role [${currentRole}] successfully decrypted ${target}.`,
        });
      } else {
        setVaultReadOutput({
          target,
          status: res.status,
          error: res.error || 'Access denied by gateway vault',
        });
        addToast({
          type: 'warning',
          title: `Access Denied (${res.status})`,
          message: res.error || 'Sealed in vault until reveal',
        });
      }
      refreshState();
    } catch (e: any) {
      addToast({ type: 'error', title: 'Vault Read Error', message: e.message });
    }
  };

  const filteredResults = matrixResults.filter(item => {
    if (filterRole !== 'all' && item.role !== filterRole) return false;
    if (filterStatus !== 'all') {
      if (filterStatus === '200' && item.status !== 200) return false;
      if (filterStatus === '403' && item.status !== 403) return false;
      if (filterStatus === '409' && item.status !== 409) return false;
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        item.action.toLowerCase().includes(q) ||
        item.resource.toLowerCase().includes(q) ||
        (item.message && item.message.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const redVaultMeta = gateway.vault.getEntryMetadata('red_attacks');
  const blueVaultMeta = gateway.vault.getEntryMetadata('blue_defense');

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16 font-mono text-xs">
      {/* Header */}
      <div className="bg-zinc-900/80 rounded-xl p-5 border border-zinc-800 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-amber-400 font-bold text-sm">
            <ShieldAlert className="h-4 w-4" />
            <span>ABAC POLICY ENFORCEMENT & REAL-TIME DENY MATRIX</span>
          </div>
          <p className="text-zinc-400 font-sans text-xs mt-1">
            Zero trust between parties: Every request carries an Ed25519-signed role token.
            The Security Gateway enforces role + round-state constraints before appending to the audit ledger.
          </p>
        </div>

        <button
          disabled={isRunningMatrix}
          onClick={runDenyMatrix}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-bold transition-all shadow-md shadow-amber-950 disabled:opacity-40"
        >
          <Play className="h-4 w-4 fill-current" />
          <span>{isRunningMatrix ? 'Testing All Pairs...' : 'Run Live Deny Matrix (56 Calls)'}</span>
        </button>
      </div>

      {/* Zero-Knowledge Vault Disclosure Inspector */}
      <div className="bg-zinc-900/90 rounded-xl border border-zinc-800 p-5 space-y-4 shadow-xl">
        <div className="flex items-center justify-between pb-3 border-b border-zinc-800">
          <div>
            <h3 className="font-bold text-zinc-100 flex items-center gap-2 text-xs">
              <Lock className="h-4 w-4 text-emerald-400" />
              AES-GCM ZERO-KNOWLEDGE VAULT DISCLOSURE INSPECTOR
            </h3>
            <p className="text-zinc-400 font-sans text-xs mt-0.5">
              Active operating role is <strong className="text-zinc-200 underline">{currentRole}</strong> in phase <strong className="text-emerald-400">{roundState}</strong>.
              Pre-reveal, Red cannot inspect Blue defenses, and Blue/Admin cannot inspect Red attacks.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Red Attack Vault Card */}
          <div className="bg-zinc-950/70 p-4 rounded-xl border border-zinc-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-bold text-rose-400">RED ATTACK SET VAULT</span>
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                redVaultMeta.unlocked ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-rose-950 text-rose-300 border border-rose-800'
              }`}>
                {redVaultMeta.unlocked ? 'UNLOCKED (POST-REVEAL)' : 'LOCKED (AES-GCM 256)'}
              </span>
            </div>
            <div className="text-[11px] text-zinc-400 space-y-1">
              <div>Key Fingerprint: <span className="text-zinc-300 font-semibold">{redVaultMeta.keyFingerprint || 'Initialized'}</span></div>
              <div>IV (12 bytes): <span className="text-zinc-300">{redVaultMeta.iv || 'Generated upon commit'}</span></div>
              <div className="truncate">Ciphertext: <span className="text-zinc-500">{redVaultMeta.ciphertextSnippet || 'Sealed'}</span></div>
            </div>
            <button
              onClick={() => handleTestVaultRead('red_vault_attack_set')}
              className="w-full py-1.5 px-3 rounded bg-zinc-800 hover:bg-zinc-750 text-zinc-200 font-bold border border-zinc-700 transition-colors"
            >
              Test Read Access as [{currentRole}]
            </button>
          </div>

          {/* Blue Defense Vault Card */}
          <div className="bg-zinc-950/70 p-4 rounded-xl border border-zinc-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-bold text-sky-400">BLUE DEFENSE CODE VAULT</span>
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                blueVaultMeta.unlocked ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-sky-950 text-sky-300 border border-sky-800'
              }`}>
                {blueVaultMeta.unlocked ? 'UNLOCKED (POST-REVEAL)' : 'LOCKED (AES-GCM 256)'}
              </span>
            </div>
            <div className="text-[11px] text-zinc-400 space-y-1">
              <div>Key Fingerprint: <span className="text-zinc-300 font-semibold">{blueVaultMeta.keyFingerprint || 'Initialized'}</span></div>
              <div>IV (12 bytes): <span className="text-zinc-300">{blueVaultMeta.iv || 'Generated upon commit'}</span></div>
              <div className="truncate">Ciphertext: <span className="text-zinc-500">{blueVaultMeta.ciphertextSnippet || 'Sealed'}</span></div>
            </div>
            <button
              onClick={() => handleTestVaultRead('blue_vault_defense_code')}
              className="w-full py-1.5 px-3 rounded bg-zinc-800 hover:bg-zinc-750 text-zinc-200 font-bold border border-zinc-700 transition-colors"
            >
              Test Read Access as [{currentRole}]
            </button>
          </div>
        </div>

        {/* Vault Output Result Box */}
        {vaultReadOutput && (
          <div className={`p-3.5 rounded-lg border text-xs space-y-1 ${
            vaultReadOutput.status === 200
              ? 'bg-emerald-950/40 border-emerald-800 text-emerald-200'
              : 'bg-amber-950/40 border-amber-800 text-amber-200'
          }`}>
            <div className="font-bold flex items-center justify-between">
              <span>Gateway Response: {vaultReadOutput.status}</span>
              <span className="text-[11px] text-zinc-400">{vaultReadOutput.target}</span>
            </div>
            {vaultReadOutput.status === 200 ? (
              <pre className="text-[11px] text-zinc-300 bg-zinc-950/60 p-2 rounded overflow-x-auto">
                {vaultReadOutput.text}
              </pre>
            ) : (
              <div className="text-amber-300 font-sans">{vaultReadOutput.error}</div>
            )}
          </div>
        )}
      </div>

      {/* Deny Matrix Results Table */}
      <div className="bg-zinc-900/90 rounded-xl border border-zinc-800 overflow-hidden shadow-xl space-y-3 p-5">
        <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-zinc-800">
          <div>
            <h3 className="font-bold text-zinc-100 text-xs">
              LIVE (ROLE × ACTION × RESOURCE) POLICY TEST MATRIX
            </h3>
            <p className="text-[11px] text-zinc-400 font-sans">
              Real HTTP status codes returned by gateway for every role permutation in state: <span className="text-emerald-400 font-bold">{roundState}</span>
            </p>
          </div>

          {/* Quick Filter */}
          <div className="flex items-center gap-2 text-[11px]">
            <span className="text-zinc-500">Filter:</span>
            {['all', 'Admin', 'Red', 'Blue', 'Auditor'].map(r => (
              <button
                key={r}
                onClick={() => setFilterRole(r)}
                className={`px-2 py-0.5 rounded ${
                  filterRole === r ? 'bg-zinc-800 text-zinc-100 font-bold border border-zinc-700' : 'text-zinc-400 hover:text-zinc-200'
                }`}
              >
                {r}
              </button>
            ))}
          </div>
        </div>

        {matrixResults.length === 0 ? (
          <div className="p-10 text-center text-zinc-500 bg-zinc-950/50 rounded-lg border border-zinc-800">
            Click "Run Live Deny Matrix" above to execute all 56 real permission evaluations.
          </div>
        ) : (
          <div className="overflow-x-auto max-h-[460px]">
            <table className="w-full text-left border-collapse text-xs">
              <thead className="bg-zinc-950 sticky top-0 text-[11px] text-zinc-400 border-b border-zinc-800">
                <tr>
                  <th className="py-2 px-3">Role</th>
                  <th className="py-2 px-3">Action</th>
                  <th className="py-2 px-3">Resource</th>
                  <th className="py-2 px-3">Gateway Status</th>
                  <th className="py-2 px-3">Policy Rationale / Reason</th>
                  <th className="py-2 px-3">Latency</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-850">
                {filteredResults.map((item, idx) => (
                  <tr key={idx} className="hover:bg-zinc-850/50 transition-colors">
                    <td className="py-2 px-3">
                      <span className={`font-bold ${
                        item.role === 'Admin' ? 'text-amber-300' : item.role === 'Red' ? 'text-rose-300' : item.role === 'Blue' ? 'text-sky-300' : 'text-emerald-300'
                      }`}>
                        {item.role}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-zinc-200">{item.action}</td>
                    <td className="py-2 px-3 text-zinc-400">{item.resource}</td>
                    <td className="py-2 px-3">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-bold border ${
                        item.status === 200
                          ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800'
                          : item.status === 403
                          ? 'bg-amber-950/60 text-amber-300 border-amber-800'
                          : 'bg-orange-950/60 text-orange-300 border-orange-800'
                      }`}>
                        {item.status} {item.status === 200 ? 'ALLOW' : item.status === 403 ? 'FORBIDDEN' : 'CONFLICT'}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-zinc-400 text-[11px] truncate max-w-sm">
                      {item.message}
                    </td>
                    <td className="py-2 px-3 text-zinc-500 text-[11px]">
                      {item.latencyMs}ms
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
