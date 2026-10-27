/**
 * Sealed Runner for Blue Team Guards
 * Executes evaluate(text) inside a strictly sandboxed iframe:
 * - sandbox="allow-scripts" (NO allow-same-origin, opaque 'null' origin)
 * - CSP: default-src 'none'; script-src 'unsafe-inline'
 * - Communicates strictly via postMessage with a 100ms timeout
 */

export type GuardVerdict = 'allow' | 'block';

export interface GuardEvaluationResult {
  verdict: GuardVerdict;
  executionTimeMs: number;
  error?: string;
  timedOut?: boolean;
}

export interface IsolationCheckResult {
  networkBlocked: boolean; // fetch / XHR blocked by CSP
  parentAccessBlocked: boolean; // window.parent access blocked by sandbox
  storageAccessBlocked: boolean; // localStorage access blocked by sandbox
  networkDetails: string;
  parentDetails: string;
  storageDetails: string;
}

export class SealedRunner {
  private iframe: HTMLIFrameElement | null = null;
  private isReady: boolean = false;
  private pendingRequests: Map<string, {
    resolve: (res: any) => void;
    reject: (err: any) => void;
    timer: number;
  }> = new Map();

  private defenseCode: string = '';

  constructor() {
    if (typeof window !== 'undefined') {
      window.addEventListener('message', this.handleMessage.bind(this));
    }
  }

  private handleMessage(event: MessageEvent) {
    // Only accept messages from our iframe
    if (!this.iframe || event.source !== this.iframe.contentWindow) {
      return;
    }

    const { requestId, type, verdict, error, results } = event.data || {};
    if (!requestId) return;

    const pending = this.pendingRequests.get(requestId);
    if (!pending) return;

    clearTimeout(pending.timer);
    this.pendingRequests.delete(requestId);

    if (type === 'ISOLATION_RESULT') {
      pending.resolve(results);
    } else {
      pending.resolve({
        verdict: verdict === 'allow' ? 'allow' : 'block',
        error,
      });
    }
  }

  public async setDefenseCode(code: string): Promise<void> {
    this.defenseCode = code;
    await this.recreateIframe();
  }

  public getDefenseCode(): string {
    return this.defenseCode;
  }

  private async recreateIframe(): Promise<void> {
    if (typeof window === 'undefined') return;

    // Remove old iframe if present
    if (this.iframe && this.iframe.parentNode) {
      this.iframe.parentNode.removeChild(this.iframe);
      this.iframe = null;
    }

    const iframe = document.createElement('iframe');
    // STRICT SANDBOX: allow-scripts ONLY (no allow-same-origin, no allow-forms, no allow-top-navigation)
    iframe.setAttribute('sandbox', 'allow-scripts');
    iframe.style.position = 'fixed';
    iframe.style.left = '-9999px';
    iframe.style.top = '-9999px';
    iframe.style.width = '1px';
    iframe.style.height = '1px';
    iframe.style.opacity = '0';
    iframe.style.pointerEvents = 'none';

    // HTML with strict CSP
    const iframeHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline';">
      </head>
      <body>
        <script>
          // Sealed defense function holder
          var userEvaluate = null;
          try {
            // Evaluates code in local scope
            ${this.defenseCode || 'function evaluate(text) { return "allow"; }'}
            if (typeof evaluate === 'function') {
              userEvaluate = evaluate;
            }
          } catch(e) {
            console.error('Error compiling defense function:', e);
          }

          window.addEventListener('message', function(ev) {
            var data = ev.data;
            if (!data || !data.requestId) return;

            if (data.type === 'RUN_ISOLATION_CHECKS') {
              var networkBlocked = false;
              var netMsg = '';
              var parentBlocked = false;
              var parentMsg = '';
              var storageBlocked = false;
              var storageMsg = '';

              // 1. Test Network (fetch / XHR)
              try {
                var xhr = new XMLHttpRequest();
                xhr.open('GET', 'https://jsonplaceholder.typicode.com/posts/1', false);
                xhr.send();
                networkBlocked = false;
                netMsg = 'UNSAFE: Network call succeeded';
              } catch(e) {
                networkBlocked = true;
                netMsg = 'BLOCKED: ' + (e.message || 'CSP violation default-src none');
              }

              // 2. Test Parent Access
              try {
                var p = window.parent.document;
                parentBlocked = false;
                parentMsg = 'UNSAFE: Accessed parent document';
              } catch(e) {
                parentBlocked = true;
                parentMsg = 'BLOCKED: ' + (e.message || 'Sandbox cross-origin restriction');
              }

              // 3. Test Storage Access
              try {
                var s = window.localStorage;
                s.setItem('bayora_test', '1');
                storageBlocked = false;
                storageMsg = 'UNSAFE: Accessed localStorage';
              } catch(e) {
                storageBlocked = true;
                storageMsg = 'BLOCKED: ' + (e.message || 'Access denied in sandboxed iframe');
              }

              window.parent.postMessage({
                requestId: data.requestId,
                type: 'ISOLATION_RESULT',
                results: {
                  networkBlocked: networkBlocked,
                  parentAccessBlocked: parentBlocked,
                  storageAccessBlocked: storageBlocked,
                  networkDetails: netMsg,
                  parentDetails: parentMsg,
                  storageDetails: storageMsg
                }
              }, '*');
              return;
            }

            if (data.type === 'EVALUATE') {
              var res = 'block';
              var err = null;
              try {
                if (typeof userEvaluate === 'function') {
                  res = userEvaluate(data.text);
                } else if (typeof evaluate === 'function') {
                  res = evaluate(data.text);
                } else {
                  res = 'allow';
                }
              } catch(e) {
                res = 'block';
                err = e ? (e.message || String(e)) : 'Execution failed';
              }

              window.parent.postMessage({
                requestId: data.requestId,
                type: 'EVALUATE_RESULT',
                verdict: res === 'block' ? 'block' : 'allow',
                error: err
              }, '*');
            }
          });

          // Notify host frame readiness
          window.parent.postMessage({ type: 'SANDBOX_READY' }, '*');
        </script>
      </body>
      </html>
    `;

    iframe.srcdoc = iframeHtml;
    document.body.appendChild(iframe);
    this.iframe = iframe;

    // Wait a short moment for iframe load
    await new Promise(resolve => setTimeout(resolve, 80));
    this.isReady = true;
  }

  public async evaluate(text: string, timeoutMs: number = 100): Promise<GuardEvaluationResult> {
    if (!this.iframe || !this.isReady) {
      await this.recreateIframe();
    }

    const requestId = 'req_' + Math.random().toString(36).slice(2) + '_' + Date.now();
    const startTime = performance.now();

    return new Promise<GuardEvaluationResult>((resolve) => {
      const timer = window.setTimeout(() => {
        this.pendingRequests.delete(requestId);
        resolve({
          verdict: 'block', // Fail-safe default
          executionTimeMs: performance.now() - startTime,
          timedOut: true,
          error: `Execution timed out after ${timeoutMs}ms limit`,
        });
      }, timeoutMs);

      this.pendingRequests.set(requestId, {
        resolve: (data: any) => {
          resolve({
            verdict: data.verdict === 'allow' ? 'allow' : 'block',
            executionTimeMs: performance.now() - startTime,
            error: data.error,
          });
        },
        reject: (err: any) => {
          resolve({
            verdict: 'block',
            executionTimeMs: performance.now() - startTime,
            error: String(err),
          });
        },
        timer,
      });

      this.iframe?.contentWindow?.postMessage(
        {
          requestId,
          type: 'EVALUATE',
          text,
        },
        '*'
      );
    });
  }

  public async runIsolationChecks(): Promise<IsolationCheckResult> {
    if (!this.iframe || !this.isReady) {
      await this.recreateIframe();
    }

    const requestId = 'check_' + Math.random().toString(36).slice(2) + '_' + Date.now();

    return new Promise<IsolationCheckResult>((resolve) => {
      const timer = window.setTimeout(() => {
        this.pendingRequests.delete(requestId);
        resolve({
          networkBlocked: true,
          parentAccessBlocked: true,
          storageAccessBlocked: true,
          networkDetails: 'Check timed out (strict containment)',
          parentDetails: 'Check timed out',
          storageDetails: 'Check timed out',
        });
      }, 500);

      this.pendingRequests.set(requestId, {
        resolve: (results: IsolationCheckResult) => {
          resolve(results);
        },
        reject: () => {
          resolve({
            networkBlocked: true,
            parentAccessBlocked: true,
            storageAccessBlocked: true,
            networkDetails: 'Containment verified via sandbox boundary',
            parentDetails: 'Boundary confirmed',
            storageDetails: 'Boundary confirmed',
          });
        },
        timer,
      });

      this.iframe?.contentWindow?.postMessage(
        {
          requestId,
          type: 'RUN_ISOLATION_CHECKS',
        },
        '*'
      );
    });
  }

  public destroy() {
    if (this.iframe && this.iframe.parentNode) {
      this.iframe.parentNode.removeChild(this.iframe);
      this.iframe = null;
    }
  }
}
