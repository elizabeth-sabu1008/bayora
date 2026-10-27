import { RoundState } from './stateMachine';

export type Role = 'Admin' | 'Red' | 'Blue' | 'Auditor';

export type Action =
  | 'transition_state'
  | 'submit_commitment'
  | 'store_vault_payload'
  | 'read_vault_payload'
  | 'query_oracle'
  | 'reveal_commitment'
  | 'verify_audit_chain'
  | 'export_evidence'
  | 'read_audit_chain'
  | 'run_sandbox_isolation';

export type Resource =
  | 'round_state'
  | 'red_commitment'
  | 'blue_commitment'
  | 'red_vault_attack_set'
  | 'blue_vault_defense_code'
  | 'oracle_endpoint'
  | 'audit_ledger'
  | 'evidence_pack'
  | 'sandbox_environment';

export interface PolicyRule {
  allowedRoles: Role[];
  allowedStates?: RoundState[];
  description: string;
}

export type DeclarativePolicy = Record<Action, Record<Resource, PolicyRule>>;

export const ACCESS_POLICY: DeclarativePolicy = {
  transition_state: {
    round_state: {
      allowedRoles: ['Admin'],
      description: 'Only Admin can transition round states',
    },
    red_commitment: { allowedRoles: [], description: 'N/A' },
    blue_commitment: { allowedRoles: [], description: 'N/A' },
    red_vault_attack_set: { allowedRoles: [], description: 'N/A' },
    blue_vault_defense_code: { allowedRoles: [], description: 'N/A' },
    oracle_endpoint: { allowedRoles: [], description: 'N/A' },
    audit_ledger: { allowedRoles: [], description: 'N/A' },
    evidence_pack: { allowedRoles: [], description: 'N/A' },
    sandbox_environment: { allowedRoles: [], description: 'N/A' },
  },
  submit_commitment: {
    red_commitment: {
      allowedRoles: ['Red'],
      allowedStates: ['COMMIT'],
      description: 'Red team submits attack commitment hash H during COMMIT phase',
    },
    blue_commitment: {
      allowedRoles: ['Blue'],
      allowedStates: ['COMMIT'],
      description: 'Blue team submits defense commitment hash H during COMMIT phase',
    },
    round_state: { allowedRoles: [], description: 'N/A' },
    red_vault_attack_set: { allowedRoles: [], description: 'N/A' },
    blue_vault_defense_code: { allowedRoles: [], description: 'N/A' },
    oracle_endpoint: { allowedRoles: [], description: 'N/A' },
    audit_ledger: { allowedRoles: [], description: 'N/A' },
    evidence_pack: { allowedRoles: [], description: 'N/A' },
    sandbox_environment: { allowedRoles: [], description: 'N/A' },
  },
  store_vault_payload: {
    red_vault_attack_set: {
      allowedRoles: ['Red'],
      allowedStates: ['COMMIT', 'LOCK'],
      description: 'Red uploads AES-GCM encrypted attack set into sealed gateway vault',
    },
    blue_vault_defense_code: {
      allowedRoles: ['Blue'],
      allowedStates: ['COMMIT', 'LOCK'],
      description: 'Blue uploads AES-GCM encrypted defense code into sealed gateway vault',
    },
    round_state: { allowedRoles: [], description: 'N/A' },
    red_commitment: { allowedRoles: [], description: 'N/A' },
    blue_commitment: { allowedRoles: [], description: 'N/A' },
    oracle_endpoint: { allowedRoles: [], description: 'N/A' },
    audit_ledger: { allowedRoles: [], description: 'N/A' },
    evidence_pack: { allowedRoles: [], description: 'N/A' },
    sandbox_environment: { allowedRoles: [], description: 'N/A' },
  },
  read_vault_payload: {
    red_vault_attack_set: {
      // Prior to REVEAL, only Red can read their own attack set.
      // At REVEAL / VERIFY / COMPLETED, Admin, Blue, and Auditor can read post-reveal data
      allowedRoles: ['Red'], // Evaluated dynamically for other roles post-reveal
      description: 'Zero-knowledge access: only Red holds access pre-reveal; public after REVEAL',
    },
    blue_vault_defense_code: {
      allowedRoles: ['Blue'],
      description: 'Zero-knowledge access: only Blue holds access pre-reveal; public after REVEAL',
    },
    round_state: { allowedRoles: ['Admin', 'Red', 'Blue', 'Auditor'], description: 'Read state' },
    red_commitment: { allowedRoles: ['Admin', 'Red', 'Blue', 'Auditor'], description: 'Public commitment hash' },
    blue_commitment: { allowedRoles: ['Admin', 'Red', 'Blue', 'Auditor'], description: 'Public commitment hash' },
    oracle_endpoint: { allowedRoles: [], description: 'N/A' },
    audit_ledger: { allowedRoles: ['Admin', 'Red', 'Blue', 'Auditor'], description: 'Public audit read' },
    evidence_pack: { allowedRoles: ['Admin', 'Auditor'], description: 'Auditor download' },
    sandbox_environment: { allowedRoles: ['Blue', 'Admin'], description: 'Sandbox status' },
  },
  query_oracle: {
    oracle_endpoint: {
      allowedRoles: ['Red'],
      allowedStates: ['EXECUTE'],
      description: 'Red submits test prompts to shaped oracle during EXECUTE phase (budget 50)',
    },
    round_state: { allowedRoles: [], description: 'N/A' },
    red_commitment: { allowedRoles: [], description: 'N/A' },
    blue_commitment: { allowedRoles: [], description: 'N/A' },
    red_vault_attack_set: { allowedRoles: [], description: 'N/A' },
    blue_vault_defense_code: { allowedRoles: [], description: 'N/A' },
    audit_ledger: { allowedRoles: [], description: 'N/A' },
    evidence_pack: { allowedRoles: [], description: 'N/A' },
    sandbox_environment: { allowedRoles: [], description: 'N/A' },
  },
  reveal_commitment: {
    red_commitment: {
      allowedRoles: ['Red'],
      allowedStates: ['REVEAL'],
      description: 'Red reveals pre-image content + 32-byte nonce during REVEAL phase',
    },
    blue_commitment: {
      allowedRoles: ['Blue'],
      allowedStates: ['REVEAL'],
      description: 'Blue reveals pre-image defense + 32-byte nonce during REVEAL phase',
    },
    round_state: { allowedRoles: [], description: 'N/A' },
    red_vault_attack_set: { allowedRoles: [], description: 'N/A' },
    blue_vault_defense_code: { allowedRoles: [], description: 'N/A' },
    oracle_endpoint: { allowedRoles: [], description: 'N/A' },
    audit_ledger: { allowedRoles: [], description: 'N/A' },
    evidence_pack: { allowedRoles: [], description: 'N/A' },
    sandbox_environment: { allowedRoles: [], description: 'N/A' },
  },
  verify_audit_chain: {
    audit_ledger: {
      allowedRoles: ['Auditor', 'Admin'],
      allowedStates: ['VERIFY', 'COMPLETED', 'SEAL', 'REVEAL'],
      description: 'Auditor cryptographically verifies tamper-evident audit hash chain and Ed25519 checkpoints',
    },
    round_state: { allowedRoles: [], description: 'N/A' },
    red_commitment: { allowedRoles: [], description: 'N/A' },
    blue_commitment: { allowedRoles: [], description: 'N/A' },
    red_vault_attack_set: { allowedRoles: [], description: 'N/A' },
    blue_vault_defense_code: { allowedRoles: [], description: 'N/A' },
    oracle_endpoint: { allowedRoles: [], description: 'N/A' },
    evidence_pack: { allowedRoles: [], description: 'N/A' },
    sandbox_environment: { allowedRoles: [], description: 'N/A' },
  },
  export_evidence: {
    evidence_pack: {
      allowedRoles: ['Admin', 'Auditor', 'Red', 'Blue'],
      allowedStates: ['COMPLETED', 'VERIFY'],
      description: 'Download signed evidence.zip bundle',
    },
    round_state: { allowedRoles: [], description: 'N/A' },
    red_commitment: { allowedRoles: [], description: 'N/A' },
    blue_commitment: { allowedRoles: [], description: 'N/A' },
    red_vault_attack_set: { allowedRoles: [], description: 'N/A' },
    blue_vault_defense_code: { allowedRoles: [], description: 'N/A' },
    oracle_endpoint: { allowedRoles: [], description: 'N/A' },
    audit_ledger: { allowedRoles: [], description: 'N/A' },
    sandbox_environment: { allowedRoles: [], description: 'N/A' },
  },
  read_audit_chain: {
    audit_ledger: {
      allowedRoles: ['Admin', 'Red', 'Blue', 'Auditor'],
      description: 'Read-only access to tamper-evident audit ledger',
    },
    round_state: { allowedRoles: ['Admin', 'Red', 'Blue', 'Auditor'], description: 'Read state' },
    red_commitment: { allowedRoles: ['Admin', 'Red', 'Blue', 'Auditor'], description: 'Read hash' },
    blue_commitment: { allowedRoles: ['Admin', 'Red', 'Blue', 'Auditor'], description: 'Read hash' },
    red_vault_attack_set: { allowedRoles: [], description: 'N/A' },
    blue_vault_defense_code: { allowedRoles: [], description: 'N/A' },
    oracle_endpoint: { allowedRoles: [], description: 'N/A' },
    evidence_pack: { allowedRoles: [], description: 'N/A' },
    sandbox_environment: { allowedRoles: [], description: 'N/A' },
  },
  run_sandbox_isolation: {
    sandbox_environment: {
      allowedRoles: ['Admin', 'Blue', 'Auditor'],
      description: 'Run CSP & isolation security checks against sandboxed iframe',
    },
    round_state: { allowedRoles: [], description: 'N/A' },
    red_commitment: { allowedRoles: [], description: 'N/A' },
    blue_commitment: { allowedRoles: [], description: 'N/A' },
    red_vault_attack_set: { allowedRoles: [], description: 'N/A' },
    blue_vault_defense_code: { allowedRoles: [], description: 'N/A' },
    oracle_endpoint: { allowedRoles: [], description: 'N/A' },
    audit_ledger: { allowedRoles: [], description: 'N/A' },
    evidence_pack: { allowedRoles: [], description: 'N/A' },
  },
};
