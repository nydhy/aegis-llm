import type { AegisMeta } from './types'

export interface SendResult {
  content: string
  aegis: AegisMeta
  blocked: boolean
}

export async function sendMessage(content: string): Promise<SendResult> {
  const res = await fetch('/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'aegis-demo',
      messages: [{ role: 'user', content }],
    }),
  })

  const json = await res.json()

  if (!res.ok) {
    return {
      content: json.error ?? 'Request blocked',
      aegis: json.aegis,
      blocked: true,
    }
  }

  return {
    content: json.message?.content ?? '',
    aegis: json.aegis,
    blocked: false,
  }
}
