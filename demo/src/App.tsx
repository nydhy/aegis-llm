import { useState, useRef, useEffect, FormEvent } from 'react'
import { sendMessage } from './api'
import type { ChatMessage, AegisMeta } from './types'
import { PRESETS } from './types'

let idCounter = 0
const uid = () => String(++idCounter)

export default function App() {
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  async function submit(prompt: string) {
    if (!prompt.trim() || loading) return
    setInput('')
    setLoading(true)

    const userMsg: ChatMessage = { id: uid(), role: 'user', content: prompt }
    const pendingMsg: ChatMessage = { id: uid(), role: 'assistant', content: '', pending: true }
    setMessages(prev => [...prev, userMsg, pendingMsg])

    const result = await sendMessage(prompt)

    setMessages(prev =>
      prev.map(m =>
        m.id === pendingMsg.id
          ? {
              id: m.id,
              role: result.blocked ? 'blocked' : 'assistant',
              content: result.content,
              aegis: result.aegis,
            }
          : m,
      ),
    )
    setLoading(false)
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    submit(input)
  }

  return (
    <div className="flex flex-col h-screen max-w-3xl mx-auto px-4">
      {/* Header */}
      <header className="flex items-center gap-3 py-5 border-b border-slate-800">
        <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-indigo-600">
          <ShieldIcon />
        </div>
        <div>
          <h1 className="text-lg font-semibold tracking-tight">aegis-llm</h1>
          <p className="text-xs text-slate-400">6-layer LLM security proxy · demo mode</p>
        </div>
        <span className="ml-auto text-xs font-mono bg-emerald-900/50 text-emerald-400 border border-emerald-800 px-2 py-1 rounded-full">
          LIVE
        </span>
      </header>

      {/* Preset buttons */}
      <div className="flex flex-wrap gap-2 py-3 border-b border-slate-800">
        {PRESETS.map(p => (
          <button
            key={p.label}
            onClick={() => submit(p.prompt)}
            disabled={loading}
            title={p.description}
            className="text-xs px-3 py-1.5 rounded-full border border-slate-700 text-slate-300 hover:border-indigo-500 hover:text-indigo-300 disabled:opacity-40 transition-colors"
          >
            {p.label}
          </button>
        ))}
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto py-4 space-y-4">
        {messages.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full text-center text-slate-500 gap-2">
            <ShieldIcon className="w-10 h-10 opacity-20" />
            <p className="text-sm">Try one of the preset prompts above<br />or type your own to see the pipeline in action.</p>
          </div>
        )}

        {messages.map(msg => (
          <Message key={msg.id} msg={msg} />
        ))}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <form onSubmit={handleSubmit} className="flex gap-2 py-4 border-t border-slate-800">
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          disabled={loading}
          placeholder="Send a message…"
          className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 text-sm placeholder:text-slate-500 focus:outline-none focus:border-indigo-500 disabled:opacity-50"
        />
        <button
          type="submit"
          disabled={loading || !input.trim()}
          className="px-4 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 rounded-lg text-sm font-medium transition-colors"
        >
          Send
        </button>
      </form>
    </div>
  )
}

function Message({ msg }: { msg: ChatMessage }) {
  if (msg.role === 'user') {
    return (
      <div className="flex justify-end">
        <div className="max-w-[80%] bg-indigo-600/20 border border-indigo-700/40 rounded-2xl rounded-tr-sm px-4 py-2.5 text-sm">
          {msg.content}
        </div>
      </div>
    )
  }

  if (msg.pending) {
    return (
      <div className="flex gap-3">
        <BotAvatar />
        <div className="flex items-center gap-1 py-3">
          <span className="w-1.5 h-1.5 rounded-full bg-slate-400 animate-bounce [animation-delay:-0.3s]" />
          <span className="w-1.5 h-1.5 rounded-full bg-slate-400 animate-bounce [animation-delay:-0.15s]" />
          <span className="w-1.5 h-1.5 rounded-full bg-slate-400 animate-bounce" />
        </div>
      </div>
    )
  }

  if (msg.role === 'blocked') {
    return (
      <div className="flex gap-3">
        <BotAvatar blocked />
        <div className="flex-1 max-w-[80%]">
          <div className="rounded-2xl rounded-tl-sm border border-red-800/60 bg-red-950/30 px-4 py-3 text-sm text-red-300">
            <p className="font-medium text-red-400 mb-1">Request blocked</p>
            <p className="text-red-300/80">{msg.aegis?.block_reason ?? msg.content}</p>
          </div>
          {msg.aegis && <AegisPanel aegis={msg.aegis} />}
        </div>
      </div>
    )
  }

  return (
    <div className="flex gap-3">
      <BotAvatar />
      <div className="flex-1 max-w-[80%]">
        <div className="rounded-2xl rounded-tl-sm bg-slate-800/60 border border-slate-700/40 px-4 py-3 text-sm leading-relaxed">
          {msg.content}
        </div>
        {msg.aegis && <AegisPanel aegis={msg.aegis} />}
      </div>
    </div>
  )
}

function AegisPanel({ aegis }: { aegis: AegisMeta }) {
  const threatColor = {
    CLEAN: 'text-emerald-400',
    SUSPICIOUS: 'text-amber-400',
    HIGH: 'text-red-400',
  }[aegis.threat_level] ?? 'text-slate-400'

  const pct = Math.min(100, Math.round((aegis.tokens_used_this_window / aegis.budget_limit) * 100))

  return (
    <div className="mt-1.5 px-3 py-2 rounded-xl bg-slate-900/80 border border-slate-800 font-mono text-[11px] text-slate-400 flex flex-wrap gap-x-4 gap-y-1">
      <span>
        threat{' '}
        <span className={`font-semibold ${threatColor}`}>{aegis.threat_level}</span>
      </span>
      <span>entropy <span className="text-slate-300">{aegis.entropy.toFixed(2)}</span></span>
      <span>
        budget{' '}
        <span className="text-slate-300">{pct}%</span>
        <span className="text-slate-600"> ({aegis.tokens_used_this_window}/{aegis.budget_limit})</span>
      </span>
      <span>
        time <span className="text-slate-300">{aegis.response_time}</span>
      </span>
      {aegis.judge_enabled && (
        <span className="text-indigo-400">judge active</span>
      )}
    </div>
  )
}

function BotAvatar({ blocked = false }: { blocked?: boolean }) {
  return (
    <div
      className={`flex-shrink-0 flex items-center justify-center w-8 h-8 rounded-lg mt-0.5 ${
        blocked ? 'bg-red-900/60' : 'bg-slate-700'
      }`}
    >
      <ShieldIcon className="w-4 h-4" />
    </div>
  )
}

function ShieldIcon({ className = 'w-5 h-5' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  )
}
