import React, { useState } from 'react';
import { ChevronDown, ChevronUp, CheckCircle, AlertTriangle, Play, Clock } from 'lucide-react';

interface ToolCallProps {
  name: string;
  params: Record<string, any>;
  result?: any;
  duration_ms?: number;
  status: 'pending' | 'success' | 'error';
}

export default function ToolCallCard({ name, params, result, duration_ms, status }: ToolCallProps) {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <div className="glass-panel rounded-lg mb-3 overflow-hidden text-xs max-w-xl self-start w-full border border-borderDark/40">
      <div 
        onClick={() => status !== 'pending' && setIsOpen(!isOpen)}
        className={`flex items-center justify-between p-3 cursor-pointer select-none transition-colors ${
          status === 'pending' ? 'bg-accentBlue/10' : 'hover:bg-cardBg/60'
        }`}
      >
        <div className="flex items-center gap-2">
          {status === 'pending' && (
            <Play className="h-3 w-3 text-accentBlue animate-pulse" />
          )}
          {status === 'success' && (
            <CheckCircle className="h-3 w-3 text-emerald-400" />
          )}
          {status === 'error' && (
            <AlertTriangle className="h-3 w-3 text-severity-critical" />
          )}
          <span className="font-semibold text-textMain font-mono">{name}</span>
        </div>
        <div className="flex items-center gap-2 text-textMuted">
          {duration_ms !== undefined && (
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3" />
              {duration_ms}ms
            </span>
          )}
          {status !== 'pending' && (isOpen ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />)}
        </div>
      </div>
      
      {isOpen && status !== 'pending' && (
        <div className="p-3 border-t border-borderDark/30 bg-background/50 space-y-2 font-mono max-h-60 overflow-y-auto">
          <div>
            <div className="text-textMuted mb-1 font-semibold uppercase tracking-wider text-[10px]">Arguments</div>
            <pre className="text-amber-300 whitespace-pre-wrap">{JSON.stringify(params, null, 2)}</pre>
          </div>
          {result && (
            <div>
              <div className="text-textMuted mb-1 font-semibold uppercase tracking-wider text-[10px]">Returned Result</div>
              <pre className="text-textMain whitespace-pre-wrap">{JSON.stringify(result, null, 2)}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
