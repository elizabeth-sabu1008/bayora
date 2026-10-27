import React, { useState } from 'react';
import { useGateway } from '../context/GatewayContext';
import { Terminal, X, ArrowDownCircle, CheckCircle2, AlertTriangle, ShieldX, Clock } from 'lucide-react';

export const LiveApiDrawer: React.FC = () => {
  const { isApiDrawerOpen, setIsApiDrawerOpen, callLogs, currentRole, currentToken } = useGateway();
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState<string>('');

  if (!isApiDrawerOpen) return null;

  const filteredLogs = callLogs.filter(log => {
    if (filterStatus !== 'all') {
      if (filterStatus === '200' && log.status !== 200) return false;
      if (filterStatus === '403' && log.status !== 403) return false;
      if (filterStatus === '409' && log.status !== 409) return false;
      if (filterStatus === 'error' && log.status < 400) return false;
    }
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      return (
        log.action.toLowerCase().includes(term) ||
        log.resource.toLowerCase().includes(term) ||
        log.role.toLowerCase().includes(term) ||
        (log.message && log.message.toLowerCase().includes(term))
      );
    }
    return true;
  });

  return (
    <div className="fixed bottom-0 left-0 right-0 z-50 bg-zinc-950 border-t border-zinc-800 shadow-2xl flex flex-col max-h-[380px] transition-all duration-200">
      {/* Drawer Header */}
      <div className="flex items-center justify-between px-4 py-2 bg-zinc-900/90 border-b border-zinc-800">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs font-mono font-semibold text-emerald-400">
            <Terminal className="h-4 w-4" />
            <span>GATEWAY AUDIT TRAFFIC</span>
          </div>
          <span className="text-[11px] font-mono text-zinc-400">
            ({filteredLogs.length} intercepted requests)
          </span>

          <div className="h-4 w-px bg-zinc-700 hidden sm:block" />

          {/* Status quick filters */}
          <div className="hidden sm:flex items-center gap-1 text-[11px] font-mono">
            <button
              onClick={() => setFilterStatus('all')}
              className={`px-2 py-0.5 rounded ${filterStatus === 'all' ? 'bg-zinc-800 text-zinc-100 font-bold' : 'text-zinc-400 hover:text-zinc-200'}`}
            >
              All
            </button>
            <button
              onClick={() => setFilterStatus('200')}
              className={`px-2 py-0.5 rounded text-emerald-400 ${filterStatus === '200' ? 'bg-emerald-950/60 border border-emerald-800' : 'hover:bg-zinc-800'}`}
            >
              200 OK
            </button>
            <button
              onClick={() => setFilterStatus('403')}
              className={`px-2 py-0.5 rounded text-amber-400 ${filterStatus === '403' ? 'bg-amber-950/60 border border-amber-800' : 'hover:bg-zinc-800'}`}
            >
              403 Forbidden
            </button>
            <button
              onClick={() => setFilterStatus('409')}
              className={`px-2 py-0.5 rounded text-orange-400 ${filterStatus === '409' ? 'bg-orange-950/60 border border-orange-800' : 'hover:bg-zinc-800'}`}
            >
              409 Conflict
            </button>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search action or resource..."
            className="text-xs bg-zinc-900 border border-zinc-700 rounded px-2.5 py-1 text-zinc-200 placeholder-zinc-500 font-mono w-44 focus:outline-none focus:border-emerald-500"
          />

          <button
            onClick={() => setIsApiDrawerOpen(false)}
            className="p-1 rounded text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Role Token Preview Strip */}
      <div className="bg-zinc-900/40 px-4 py-1 text-[11px] font-mono text-zinc-500 flex items-center justify-between border-b border-zinc-800/60">
        <div className="flex items-center gap-2 truncate">
          <span className="text-zinc-400 font-semibold">Active Role Token:</span>
          <span className="text-zinc-400 font-mono text-[10px] bg-zinc-900 px-1.5 py-0.5 rounded border border-zinc-800 truncate max-w-md">
            {currentToken ? currentToken.slice(0, 50) + '...' + currentToken.slice(-16) : 'Generating...'}
          </span>
        </div>
        <span className="text-[10px] text-zinc-500">Every request carries an Ed25519 signed JWT equivalent</span>
      </div>

      {/* Logs Table */}
      <div className="overflow-y-auto flex-1 font-mono text-xs">
        {filteredLogs.length === 0 ? (
          <div className="p-8 text-center text-zinc-500">
            No gateway requests match the current filter. Perform actions in the Round Wizard or Matrix to see traffic.
          </div>
        ) : (
          <table className="w-full text-left border-collapse">
            <thead className="bg-zinc-900/80 sticky top-0 text-[11px] text-zinc-400 border-b border-zinc-800">
              <tr>
                <th className="py-1.5 px-3">Time</th>
                <th className="py-1.5 px-3">Status</th>
                <th className="py-1.5 px-3">Role</th>
                <th className="py-1.5 px-3">Action</th>
                <th className="py-1.5 px-3">Target Resource</th>
                <th className="py-1.5 px-3">Latency</th>
                <th className="py-1.5 px-3">Message / Error</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-850">
              {filteredLogs.map(log => {
                const statusColor =
                  log.status === 200
                    ? 'text-emerald-400 bg-emerald-950/40 border-emerald-800/50'
                    : log.status === 403
                    ? 'text-amber-400 bg-amber-950/40 border-amber-800/50'
                    : log.status === 409
                    ? 'text-orange-400 bg-orange-950/40 border-orange-800/50'
                    : 'text-rose-400 bg-rose-950/40 border-rose-800/50';

                const roleColor =
                  log.role === 'Admin'
                    ? 'text-amber-300'
                    : log.role === 'Red'
                    ? 'text-rose-300'
                    : log.role === 'Blue'
                    ? 'text-sky-300'
                    : log.role === 'Auditor'
                    ? 'text-emerald-300'
                    : 'text-zinc-400';

                return (
                  <tr key={log.id} className="hover:bg-zinc-900/50 transition-colors">
                    <td className="py-1 px-3 text-zinc-500 text-[11px]">
                      {new Date(log.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 })}
                    </td>
                    <td className="py-1 px-3">
                      <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[11px] font-bold border ${statusColor}`}>
                        {log.status}
                      </span>
                    </td>
                    <td className="py-1 px-3">
                      <span className={`font-semibold ${roleColor}`}>{log.role}</span>
                    </td>
                    <td className="py-1 px-3 text-zinc-200">{log.action}</td>
                    <td className="py-1 px-3 text-zinc-400">{log.resource}</td>
                    <td className="py-1 px-3 text-zinc-400 text-[11px]">
                      {log.latencyMs}ms
                    </td>
                    <td className="py-1 px-3 text-zinc-400 text-[11px] truncate max-w-xs">
                      {log.message || (log.status === 200 ? 'Authorized & Appended to Audit Chain' : '-')}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
