import React, { useState, useRef, useEffect } from 'react';
import { Send, ShieldAlert, Cpu, Sparkles, Plus, Terminal, RefreshCw, Layers } from 'lucide-react';
import ToolCallCard from './ToolCallCard';

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  agent?: string;
  timestamp: string;
  toolCalls?: Array<{
    name: string;
    params: Record<string, any>;
    result?: any;
    duration_ms?: number;
    status: 'pending' | 'success' | 'error';
  }>;
}

export default function ChatWindow() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [activeAgent, setActiveAgent] = useState('General Orchestrator');
  const [agentStatus, setAgentStatus] = useState('Idle');
  const [sessionId, setSessionId] = useState<string>('');
  const [apiHealth, setApiHealth] = useState<'online' | 'offline'>('online');
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Generate new Session ID on startup
    setSessionId(`sess_${Math.random().toString(36).substring(2, 9)}`);
    checkHealth();
  }, []);

  const checkHealth = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/health');
      if (res.ok) setApiHealth('online');
      else setApiHealth('offline');
    } catch {
      setApiHealth('offline');
    }
  };

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isLoading, agentStatus]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isLoading) return;

    const userMessageText = input.trim();
    setInput('');
    setIsLoading(true);

    const userMessage: Message = {
      id: `msg_user_${Date.now()}`,
      role: 'user',
      content: userMessageText,
      timestamp: new Date().toLocaleTimeString()
    };

    setMessages(prev => [...prev, userMessage]);

    // Create placeholder assistant message
    const assistantMessageId = `msg_ast_${Date.now()}`;
    const assistantMessage: Message = {
      id: assistantMessageId,
      role: 'assistant',
      content: '',
      timestamp: new Date().toLocaleTimeString(),
      toolCalls: []
    };

    setMessages(prev => [...prev, assistantMessage]);

    try {
      const response = await fetch('http://localhost:8000/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: userMessageText,
          session_id: sessionId,
          history: messages.map(m => ({ role: m.role, content: m.content }))
        })
      });

      if (!response.body) throw new Error('No response body stream');

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      let currentText = '';
      let activeTools: Message['toolCalls'] = [];

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        
        // Save the last partial line back to the buffer
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (!line.trim()) continue;
          if (line.startsWith('data: ')) {
            const dataStr = line.slice(6).trim();
            const eventMatch = lines[lines.indexOf(line) - 1]?.match(/^event:\s*(.+)$/);
            const eventType = eventMatch ? eventMatch[1].trim() : 'text_chunk';

            try {
              const data = JSON.parse(dataStr);
              
              if (line.includes('event: agent_state')) {
                setActiveAgent(data.agent);
                setAgentStatus(data.message);
              } 
              else if (line.includes('event: tool_start')) {
                setAgentStatus(`Executing tool: ${data.name}...`);
                const newTool = {
                  name: data.name,
                  params: data.params,
                  status: 'pending' as const
                };
                activeTools = [...(activeTools || []), newTool];
                setMessages(prev => prev.map(m => m.id === assistantMessageId ? { ...m, toolCalls: activeTools } : m));
              } 
              else if (line.includes('event: tool_complete')) {
                setAgentStatus(`Completed tool: ${data.name}`);
                activeTools = activeTools.map(t => 
                  t.name === data.name 
                    ? { ...t, status: data.status, duration_ms: data.duration_ms, result: data.result }
                    : t
                );
                setMessages(prev => prev.map(m => m.id === assistantMessageId ? { ...m, toolCalls: activeTools } : m));
              } 
              else if (line.includes('event: text_chunk')) {
                currentText += data.text;
                setMessages(prev => prev.map(m => m.id === assistantMessageId ? { ...m, content: currentText, agent: activeAgent } : m));
              }
              else if (line.includes('event: complete')) {
                setIsLoading(false);
                setAgentStatus('Response complete.');
              }
            } catch (err) {
              // Raw parsing fallback
              if (dataStr) {
                try {
                  const rawObj = JSON.parse(dataStr);
                  if (rawObj.text) {
                    currentText += rawObj.text;
                    setMessages(prev => prev.map(m => m.id === assistantMessageId ? { ...m, content: currentText } : m));
                  }
                } catch {}
              }
            }
          }
        }
      }
    } catch (err) {
      console.error('Error fetching stream:', err);
      setMessages(prev => prev.map(m => m.id === assistantMessageId ? {
        ...m,
        content: 'Error: Connection failed or read-only violation intercepted.'
      } : m));
      setIsLoading(false);
      setAgentStatus('Error state.');
    }
  };

  const startNewSession = () => {
    setSessionId(`sess_${Math.random().toString(36).substring(2, 9)}`);
    setMessages([]);
    setActiveAgent('General Orchestrator');
    setAgentStatus('Idle');
  };

  return (
    <div className="flex h-full w-full">
      {/* Sidebar */}
      <div className="w-64 bg-cardBg border-r border-borderDark flex flex-col justify-between p-4 shrink-0">
        <div className="space-y-4">
          <div className="flex items-center gap-2 text-accentBlue font-bold text-lg select-none">
            <Layers className="h-6 w-6" />
            <span>Falcon AI Copilot</span>
          </div>
          <button 
            onClick={startNewSession}
            className="w-full flex items-center justify-center gap-2 bg-accentBlue hover:bg-accentBlue/80 text-white rounded-lg p-2 text-sm font-semibold transition-colors shadow-lg shadow-accentBlue/20"
          >
            <Plus className="h-4 w-4" />
            New Investigation
          </button>
          
          <div className="pt-4 border-t border-borderDark space-y-2">
            <div className="text-[10px] text-textMuted uppercase tracking-wider font-semibold">Active Session</div>
            <div className="font-mono text-xs bg-background/50 border border-borderDark p-2 rounded text-amber-300 overflow-x-auto">
              {sessionId}
            </div>
          </div>
        </div>

        <div className="space-y-3">
          <div className="flex items-center justify-between text-xs border-t border-borderDark pt-4">
            <span className="text-textMuted flex items-center gap-1"><Cpu className="h-3 w-3" /> API Health</span>
            <span className={`inline-block h-2.5 w-2.5 rounded-full ${apiHealth === 'online' ? 'bg-emerald-400' : 'bg-red-400'}`} />
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="text-textMuted flex items-center gap-1"><Terminal className="h-3 w-3" /> Mode</span>
            <span className="text-emerald-400 border border-emerald-400/30 px-1.5 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider bg-emerald-950/20">Read-Only</span>
          </div>
        </div>
      </div>

      {/* Main chat section */}
      <div className="flex-1 flex flex-col h-full bg-background justify-between">
        {/* Status Bar */}
        <div className="h-14 border-b border-borderDark bg-cardBg/30 flex items-center justify-between px-6 shrink-0">
          <div className="flex items-center gap-3">
            <div className="h-2 w-2 rounded-full bg-accentBlue animate-ping" />
            <div>
              <div className="text-xs text-textMuted font-mono">Specialist Agent</div>
              <div className="text-sm font-bold text-textMain">{activeAgent}</div>
            </div>
          </div>
          <div className="text-right">
            <div className="text-xs text-textMuted font-mono">Agent Activity</div>
            <div className="text-xs text-amber-300 font-mono italic max-w-sm truncate">{agentStatus}</div>
          </div>
        </div>

        {/* Message Panel */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {messages.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center space-y-4 max-w-md mx-auto">
              <Sparkles className="h-10 w-10 text-accentBlue" />
              <h2 className="text-lg font-bold text-textMain">Welcome to Falcon AI Copilot</h2>
              <p className="text-sm text-textMuted">
                Ask about detections, incidents, host statuses, prevent policies, threat actors, or generate FQL/FalconPy scripts.
              </p>
              <div className="grid grid-cols-2 gap-2 w-full pt-2">
                <button onClick={() => setInput("What happened in the last 24 hours?")} className="text-left text-xs bg-cardBg hover:bg-cardBg/80 p-3 rounded border border-borderDark text-textMain transition-colors">
                  What happened in the last 24 hours?
                </button>
                <button onClick={() => setInput("Find LSASS access FQL query")} className="text-left text-xs bg-cardBg hover:bg-cardBg/80 p-3 rounded border border-borderDark text-textMain transition-colors">
                  Find LSASS access FQL query
                </button>
                <button onClick={() => setInput("How does Falcon Prevent work?")} className="text-left text-xs bg-cardBg hover:bg-cardBg/80 p-3 rounded border border-borderDark text-textMain transition-colors">
                  How does Falcon Prevent work?
                </button>
                <button onClick={() => setInput("Export prevention policies python script")} className="text-left text-xs bg-cardBg hover:bg-cardBg/80 p-3 rounded border border-borderDark text-textMain transition-colors">
                  Export prevention policies script
                </button>
              </div>
            </div>
          ) : (
            messages.map((msg) => (
              <div 
                key={msg.id} 
                className={`flex gap-4 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                {msg.role === 'assistant' && (
                  <div className="h-8 w-8 rounded-full bg-accentBlue/20 flex items-center justify-center border border-accentBlue/40 shrink-0">
                    <Terminal className="h-4 w-4 text-accentBlue" />
                  </div>
                )}
                
                <div className={`max-w-3xl space-y-2`}>
                  {msg.role === 'assistant' && msg.toolCalls && msg.toolCalls.map((t, idx) => (
                    <ToolCallCard 
                      key={idx}
                      name={t.name}
                      params={t.params}
                      status={t.status}
                      duration_ms={t.duration_ms}
                      result={t.result}
                    />
                  ))}
                  
                  {msg.content && (
                    <div className={`p-4 rounded-xl text-sm leading-relaxed border ${
                      msg.role === 'user' 
                        ? 'bg-accentBlue/10 border-accentBlue/30 text-textMain'
                        : 'bg-cardBg/50 border-borderDark/60 text-textMain shadow-sm'
                    }`}>
                      <div className="whitespace-pre-wrap font-sans">{msg.content}</div>
                      {msg.role === 'assistant' && msg.agent && (
                        <div className="mt-2 text-[10px] text-textMuted uppercase font-mono tracking-wider flex items-center gap-1 border-t border-borderDark/20 pt-1">
                          <Cpu className="h-3 w-3 text-accentBlue" /> Generated by {msg.agent}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            ))
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Input Form */}
        <div className="p-6 border-t border-borderDark shrink-0 bg-background">
          <form onSubmit={handleSubmit} className="flex gap-3 bg-cardBg border border-borderDark rounded-xl p-2 focus-within:border-accentBlue/50 transition-colors">
            <input 
              type="text" 
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask Falcon AI Copilot..." 
              className="flex-1 bg-transparent border-0 outline-none focus:ring-0 text-sm px-3 text-textMain placeholder:text-textMuted"
            />
            <button 
              type="submit" 
              disabled={isLoading || !input.trim()}
              className="h-9 w-9 bg-accentBlue hover:bg-accentBlue/80 disabled:opacity-40 disabled:hover:bg-accentBlue flex items-center justify-center text-white rounded-lg transition-colors cursor-pointer"
            >
              <Send className="h-4 w-4" />
            </button>
          </form>
          <div className="flex items-center gap-1 text-[10px] text-textMuted mt-2 px-1">
            <ShieldAlert className="h-3.5 w-3.5 text-emerald-400" />
            <span>Strict read-only safety limits are enforced. Mutating CrowdStrike actions will be blocked automatically.</span>
          </div>
        </div>
      </div>
    </div>
  );
}
