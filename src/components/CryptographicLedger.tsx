import React, { useState } from 'react';
import { useGateway } from '../context/GatewayContext';
import { AuditEvent, GENESIS_PREV_HASH } from '../core/auditChain';
import { canonicalJSON } from '../core/crypto';
import {
  Layers,
  Copy,
  Check,
  Search,
  Filter,
  Link,
  ChevronDown,
  ChevronRight,
  ShieldCheck,
  Hash,
  Clock,
  User,
} from 'lucide-react';

export const CryptographicLedger: React.FC = () => {
  const { gateway } = useGateway();
  const events = gateway.auditChain.getEvents();
  const checkpoints = gateway.auditChain.getCheckpoints();

  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [selectedEventIndex, setSelectedEventIndex] = useState<number | null>(null);
  const [filterActor, setFilterActor] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState<string>('');

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const filteredEvents = events.filter(evt => {
    if (filterActor !== 'all' && evt.actor !== filterActor) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      return (
        evt.type.toLowerCase().includes(term) ||
        evt.zone.toLowerCase().includes(term) ||
        evt.entry_hash.toLowerCase().includes(term) ||
        evt.prev_hash.toLowerCase().includes(term) ||
        JSON.stringify(evt.payload).toLowerCase().includes(term)
      );
    }
    return true;
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16 font-mono">
      {/* Header */}
      <div className="bg-zinc-900/80 rounded-xl p-5 border border-zinc-800 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
            <Layers className="h-4 w-4" />
            <span>IMMUTABLE CRYPTOGRAPHIC AUDIT LEDGER</span>
          </div>
          <p className="text-xs text-zinc-400 font-sans mt-1">
            Append-only hash chain where <code className="text-emerald-300">entry_hash = SHA256(prev_hash + canonicalJSON(event))</code>.
            Genesis begins with 64 zeros. Every transaction, allowed or denied, is permanently sealed.
          </p>
        </div>

        <div className="flex items-center gap-3 text-xs">
          <div className="bg-zinc-950 px-3 py-1.5 rounded-lg border border-zinc-800 flex items-center gap-2">
            <span className="text-zinc-500">Total Blocks:</span>
            <span className="font-bold text-emerald-400">{events.length}</span>
          </div>
          <div className="bg-zinc-950 px-3 py-1.5 rounded-lg border border-zinc-800 flex items-center gap-2">
            <span className="text-zinc-500">Checkpoints:</span>
            <span className="font-bold text-sky-400">{checkpoints.length}</span>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-zinc-900/50 p-3 rounded-lg border border-zinc-800 text-xs">
        <div className="flex items-center gap-2">
          <Filter className="h-3.5 w-3.5 text-zinc-500" />
          <span className="text-zinc-400 font-medium">Filter Actor:</span>
          {['all', 'Admin', 'Red', 'Blue', 'Auditor', 'Gateway'].map(act => (
            <button
              key={act}
              onClick={() => setFilterActor(act)}
              className={`px-2 py-0.5 rounded transition-colors ${
                filterActor === act
                  ? 'bg-zinc-800 text-emerald-400 font-bold border border-zinc-700'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              {act}
            </button>
          ))}
        </div>

        <div className="relative">
          <Search className="h-3.5 w-3.5 text-zinc-500 absolute left-2.5 top-2.5" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search hash, type, payload..."
            className="bg-zinc-900 border border-zinc-700/80 rounded px-2.5 py-1 pl-8 text-xs text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-emerald-500 w-64"
          />
        </div>
      </div>

      {/* Table of Events */}
      <div className="bg-zinc-900/90 rounded-xl border border-zinc-800 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead className="bg-zinc-950/80 text-[11px] text-zinc-400 border-b border-zinc-800">
              <tr>
                <th className="py-2.5 px-3 w-16">Index</th>
                <th className="py-2.5 px-3 w-28">Timestamp</th>
                <th className="py-2.5 px-3 w-28">Actor / Zone</th>
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3 w-20">Status</th>
                <th className="py-2.5 px-3">Previous Block Hash</th>
                <th className="py-2.5 px-3">Entry Hash</th>
                <th className="py-2.5 px-3 w-16 text-center">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-850">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-10 text-center text-zinc-500 font-sans">
                    No events in audit ledger yet. Start a round or invoke a gateway action to append blocks.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((evt, i) => {
                  const isSelected = selectedEventIndex === evt.index;
                  const isGenesis = evt.index === 0;

                  const roleBadgeColor =
                    evt.actor === 'Admin'
                      ? 'text-amber-400 bg-amber-950/40 border-amber-800/50'
                      : evt.actor === 'Red'
                      ? 'text-rose-400 bg-rose-950/40 border-rose-800/50'
                      : evt.actor === 'Blue'
                      ? 'text-sky-400 bg-sky-950/40 border-sky-800/50'
                      : evt.actor === 'Auditor'
                      ? 'text-emerald-400 bg-emerald-950/40 border-emerald-800/50'
                      : 'text-zinc-400 bg-zinc-800/40 border-zinc-700/50';

                  return (
                    <React.Fragment key={evt.index}>
                      <tr
                        id={`event-row-${evt.index}`}
                        className={`hover:bg-zinc-850/60 transition-colors ${
                          isSelected ? 'bg-zinc-800/50' : ''
                        }`}
                      >
                        {/* Index */}
                        <td className="py-2.5 px-3 font-bold text-zinc-300">
                          #{evt.index}
                        </td>

                        {/* Timestamp */}
                        <td className="py-2.5 px-3 text-zinc-500 text-[11px] whitespace-nowrap">
                          {new Date(evt.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                        </td>

                        {/* Actor / Zone */}
                        <td className="py-2.5 px-3 whitespace-nowrap">
                          <div className="flex flex-col">
                            <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold border w-fit ${roleBadgeColor}`}>
                              {evt.actor}
                            </span>
                            <span className="text-[10px] text-zinc-500 mt-0.5">{evt.zone}</span>
                          </div>
                        </td>

                        {/* Event Type */}
                        <td className="py-2.5 px-3">
                          <span className="font-semibold text-zinc-200">{evt.type}</span>
                        </td>

                        {/* Status */}
                        <td className="py-2.5 px-3">
                          <span
                            className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              evt.status === 200
                                ? 'text-emerald-400 bg-emerald-950/50 border border-emerald-800/60'
                                : evt.status === 403
                                ? 'text-amber-400 bg-amber-950/50 border border-amber-800/60'
                                : evt.status === 409
                                ? 'text-orange-400 bg-orange-950/50 border border-orange-800/60'
                                : 'text-rose-400 bg-rose-950/50 border border-rose-800/60'
                            }`}
                          >
                            {evt.status}
                          </span>
                        </td>

                        {/* Prev Hash */}
                        <td className="py-2.5 px-3 font-mono text-[11px]">
                          <div className="flex items-center gap-1.5">
                            {isGenesis ? (
                              <span className="text-zinc-500 italic">GENESIS (64 zeros)</span>
                            ) : (
                              <>
                                <button
                                  onClick={() => {
                                    const targetRow = document.getElementById(`event-row-${evt.index - 1}`);
                                    targetRow?.scrollIntoView({ behavior: 'smooth', block: 'center' });
                                    setSelectedEventIndex(evt.index - 1);
                                  }}
                                  title="Linked to previous block entry_hash"
                                  className="text-zinc-400 hover:text-emerald-400 underline decoration-dotted flex items-center gap-1"
                                >
                                  <Link className="h-3 w-3 text-zinc-600" />
                                  <span>{evt.prev_hash.slice(0, 10)}...{evt.prev_hash.slice(-6)}</span>
                                </button>
                                <button
                                  onClick={() => copyToClipboard(evt.prev_hash)}
                                  className="p-1 hover:text-emerald-400 text-zinc-500"
                                  title="Copy prev_hash"
                                >
                                  {copiedHash === evt.prev_hash ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                                </button>
                              </>
                            )}
                          </div>
                        </td>

                        {/* Entry Hash */}
                        <td className="py-2.5 px-3 font-mono text-[11px]">
                          <div className="flex items-center gap-1.5 text-emerald-400 font-bold">
                            <span>{evt.entry_hash.slice(0, 12)}...{evt.entry_hash.slice(-6)}</span>
                            <button
                              onClick={() => copyToClipboard(evt.entry_hash)}
                              className="p-1 hover:text-emerald-300 text-zinc-500"
                              title="Copy entry_hash"
                            >
                              {copiedHash === evt.entry_hash ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                            </button>
                          </div>
                        </td>

                        {/* Expand / Inspect */}
                        <td className="py-2.5 px-3 text-center">
                          <button
                            onClick={() => setSelectedEventIndex(isSelected ? null : evt.index)}
                            className="p-1 rounded text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800"
                          >
                            {isSelected ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                          </button>
                        </td>
                      </tr>

                      {/* Expanded Payload Row */}
                      {isSelected && (
                        <tr className="bg-zinc-950/80">
                          <td colSpan={8} className="p-4 border-b border-zinc-800/80">
                            <div className="space-y-3 font-mono text-xs">
                              <div className="flex items-center justify-between text-zinc-400 pb-2 border-b border-zinc-800">
                                <span className="font-bold text-zinc-300">
                                  BLOCK #{evt.index} CANONICAL PAYLOAD
                                </span>
                                <span className="text-[11px] text-zinc-500">
                                  Evaluated via canonicalJSON() serializer
                                </span>
                              </div>

                              <div className="bg-zinc-900 p-3 rounded-lg border border-zinc-800 overflow-x-auto text-zinc-300">
                                <pre className="text-[11px] leading-relaxed">
                                  {canonicalJSON(evt.payload)}
                                </pre>
                              </div>

                              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px] text-zinc-400">
                                <div>
                                  <span className="text-zinc-500">Full Prev Hash:</span>
                                  <div className="break-all font-mono text-zinc-300 bg-zinc-900/60 p-1.5 rounded mt-0.5 border border-zinc-850">
                                    {evt.prev_hash}
                                  </div>
                                </div>
                                <div>
                                  <span className="text-zinc-500">Full Entry Hash:</span>
                                  <div className="break-all font-mono text-emerald-400 bg-zinc-900/60 p-1.5 rounded mt-0.5 border border-zinc-850">
                                    {evt.entry_hash}
                                  </div>
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
