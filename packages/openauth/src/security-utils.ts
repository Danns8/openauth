import type { RegisteredClients } from "./security.js"

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

export function randomSecret(): string {
  return base64url(crypto.getRandomValues(new Uint8Array(32)))
}

export async function hashSecret(value: string): Promise<string> {
  return base64url(new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
  ))
}

export function parseRefreshToken(value: unknown): { familyID: string; token: string } | undefined {
  if (typeof value !== "string") return
  const parts = /^v2\.([0-9a-f-]{36})\.([A-Za-z0-9_-]{43})$/.exec(value)
  if (parts) return { familyID: parts[1], token: value }
}

export function newRefreshToken(familyID: string = crypto.randomUUID()): string {
  return `v2.${familyID}.${randomSecret()}`
}

export function validPasswordOrigin(request: Request, expectedOrigin: string): boolean {
  if (request.headers.get("Sec-Fetch-Site") === "cross-site") return false
  const origin = request.headers.get("Origin")
  // 无 Origin 的客户端仍须提供不可猜测的 CSRF token，不能只依靠本函数认证。
  return origin === null || origin === expectedOrigin
}

export function passwordReturnURL(value: string | undefined, fallback: string): string | undefined {
  if (!value) return fallback
  if (/[\u0000-\u0020\u007f\\]/.test(value)) return
  try {
    const result = new URL(value, fallback)
    if (result.origin !== new URL(fallback).origin || result.username ||
        result.password || result.hash) return
    return result.toString()
  } catch { return }
}

function formEncode(value: string) {
  return new URLSearchParams({ v: value }).toString().slice(2)
}

export function basicCredentials(clientID: string, secret: string): string {
  return "Basic " + btoa(`${formEncode(clientID)}:${formEncode(secret)}`)
}

async function equalSecret(a: string, b: string) {
  const [left, right] = await Promise.all([hashSecret(a), hashSecret(b)])
  let difference = 0
  for (let i = 0; i < left.length; i++) difference |= left.charCodeAt(i) ^ right.charCodeAt(i)
  return difference === 0
}

/** 客户端类型在启动时确定，不能由请求是否携带 secret 决定。 */
export function clientAuthenticator(clients?: RegisteredClients) {
  const registry = new Map<string, string | undefined>()
  for (const [id, client] of Object.entries(clients ?? {})) {
    if (client.clientSecret !== undefined &&
        (typeof client.clientSecret !== "string" || client.clientSecret.length < 32)) {
      throw new Error("Confidential client secrets must contain at least 32 characters")
    }
    registry.set(id, client.clientSecret)
  }
  return async (request: Request, form: FormData): Promise<string | undefined> => {
    let clientID = form.get("client_id")?.toString()
    let secret = form.get("client_secret")?.toString()
    const authorization = request.headers.get("Authorization")
    if (authorization !== null) {
      if (!/^Basic /i.test(authorization) || secret !== undefined) return
      try {
        const decoded = atob(authorization.slice(6))
        const at = decoded.indexOf(":")
        if (at < 0) return
        const username = decodeURIComponent(decoded.slice(0, at).replace(/\+/g, " "))
        secret = decodeURIComponent(decoded.slice(at + 1).replace(/\+/g, " "))
        if (clientID !== undefined && clientID !== username) return
        clientID = username
      } catch { return }
    }
    if (!clientID || (clients && !registry.has(clientID))) return
    const expected = registry.get(clientID)
    if (expected !== undefined) {
      if (secret === undefined || !(await equalSecret(secret, expected))) return
    } else if (secret !== undefined) {
      return
    }
    return clientID
  }
}

/**
 * 有上限的缓存；请求合并和失败冷却限制未知 kid 带来的远程请求。
 * 加载失败不无限沿用过期数据，密钥撤销才有可说明的缓存上限。
 */
export function expiringCache<T>(load: () => Promise<T>, ttl = 30_000, cooldown = 5_000) {
  let cached: { value: T; at: number } | undefined
  let pending: Promise<T> | undefined
  let attemptedAt = -Infinity
  let failed: unknown
  return async (force = false): Promise<T> => {
    const now = Date.now()
    const fresh = cached && now >= cached.at && now - cached.at < ttl
    if (fresh && (!force || now - attemptedAt < cooldown)) return cached!.value
    if (pending) return pending
    if (failed && now >= attemptedAt && now - attemptedAt < cooldown) throw failed
    attemptedAt = now
    pending = Promise.resolve().then(load).then((value) => {
      cached = { value, at: Date.now() }
      failed = undefined
      return value
    }).catch((error) => {
      failed = error
      throw error
    }).finally(() => {
      pending = undefined
    })
    return pending
  }
}
