import JSZip from 'jszip';
import { sha256Hex, canonicalJSON } from './crypto';
import { SecurityGateway } from './gateway';
import { ACCESS_POLICY } from './policy';

export interface EvidenceBundleFiles {
  'events.json': string;
  'commitments.json': string;
  'checkpoints.json': string;
  'public_key.txt': string;
  'policy.json': string;
  'results.json': string;
  'manifest.json'?: string;
}

export class EvidenceManager {
  /**
   * Generates all evidentiary files from the gateway state and packages them into a JSZip
   */
  public static async generateEvidenceZip(gateway: SecurityGateway): Promise<Blob> {
    const zip = new JSZip();

    const events = gateway.auditChain.getEvents();
    const commitments = gateway.commitReveal.getAllCommitments();
    const checkpoints = gateway.auditChain.getCheckpoints();
    const pubKeyHex = gateway.gatewayPublicKeyHex;
    const internalOracleRecords = gateway.oracle.getInternalAuditRecords();

    const findings = internalOracleRecords.filter(r => r.canaryLeaked);
    const blockedCount = internalOracleRecords.filter(r => r.verdict === 'BLOCKED').length;
    const passedCount = internalOracleRecords.filter(r => r.verdict === 'PASSED').length;
    const timeoutCount = internalOracleRecords.filter(r => r.verdict === 'TIMEOUT').length;

    const resultsData = {
      roundStatus: gateway.stateMachine.getState(),
      generatedAt: new Date().toISOString(),
      queryBudget: 50,
      queriesExecuted: gateway.oracle.getQueriesCount(),
      verdictSummary: {
        blocked: blockedCount,
        passed: passedCount,
        timeouts: timeoutCount,
      },
      canaryTesting: {
        canaryString: gateway.oracle.getCanaryString(),
        leaksDetectedCount: findings.length,
        isSafe: findings.length === 0,
      },
      detailedOracleQueries: internalOracleRecords,
    };

    const files: Record<string, string> = {
      'events.json': canonicalJSON(events),
      'commitments.json': canonicalJSON(commitments),
      'checkpoints.json': canonicalJSON(checkpoints),
      'public_key.txt': `BAYORA GATEWAY ED25519 PUBLIC KEY:\n${pubKeyHex}\n\nAlgorithm: Ed25519 (RFC 8032)\nHash: SHA-512\nGenerated: ${new Date().toISOString()}\nUse this key to independently verify all checkpoints and role tokens in offline auditors.`,
      'policy.json': canonicalJSON(ACCESS_POLICY),
      'results.json': canonicalJSON(resultsData),
    };

    // Compute real SHA-256 hash for every file in the evidence pack
    const manifestFileHashes: Record<string, string> = {};
    for (const [fileName, fileContent] of Object.entries(files)) {
      manifestFileHashes[fileName] = await sha256Hex(fileContent);
      zip.file(fileName, fileContent);
    }

    const manifestData = {
      manifestVersion: '1.0-BAYORA',
      algorithm: 'SHA-256',
      generatedAt: new Date().toISOString(),
      gatewayPublicKey: pubKeyHex,
      files: manifestFileHashes,
    };

    const manifestContent = canonicalJSON(manifestData);
    zip.file('manifest.json', manifestContent);

    return zip.generateAsync({
      type: 'blob',
      compression: 'DEFLATE',
      compressionOptions: { level: 9 },
    });
  }

  /**
   * Browser file download trigger
   */
  public static triggerDownload(blob: Blob, filename: string = 'evidence.zip') {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 1500);
  }
}
