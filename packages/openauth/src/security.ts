/** @internal */
export type RegisteredClients = Record<string, { redirectURIs: readonly string[] }>

/** Validate syntax only. Authorization still requires an exact registered match. */
export function isSafeRedirectURI(value: unknown): value is string {
  if (typeof value !== "string" || !/^https?:\/\//i.test(value) || /[\u0000-\u0020\u007f\\]/.test(value) || value.includes("#")) {
    return false
  }
  try {
    const url = new URL(value)
    if (url.username || url.password) return false
    return url.protocol === "https:" || (
      url.protocol === "http:" &&
      ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
    )
  } catch {
    return false
  }
}

/** Copy registration data at startup; never derive trust from a request hostname. */
export function registeredRedirects(clients: RegisteredClients = {}) {
  const registry = new Map<string, Set<string>>()
  for (const [clientID, client] of Object.entries(clients)) {
    if (!clientID || !Array.isArray(client?.redirectURIs) || !client.redirectURIs.length) {
      throw new Error("Each client must have an ID and registered redirect URIs")
    }
    for (const uri of client.redirectURIs) {
      if (!isSafeRedirectURI(uri)) throw new Error(`Invalid redirect URI for client ${clientID}`)
    }
    registry.set(clientID, new Set(client.redirectURIs))
  }
  return (clientID: string, redirectURI: string) =>
    isSafeRedirectURI(redirectURI) && registry.get(clientID)?.has(redirectURI) === true
}

export function issuerOrigin(value: string): string {
  if (!isSafeRedirectURI(value)) throw new Error("Invalid issuer URL")
  const url = new URL(value)
  if (url.pathname !== "/" || url.search || value.includes("?")) {
    throw new Error("Issuer must be an origin without a path or query")
  }
  return url.origin
}

interface StateCookie<T> {
  version: 1
  purpose: string
  expiresAt: number
  value: T
}

export function stateCookie<T>(purpose: string, maxAge: number, value: T, now = Date.now()): StateCookie<T> {
  if (!purpose || !Number.isSafeInteger(maxAge) || maxAge <= 0 || !Number.isSafeInteger(now + maxAge * 1000)) {
    throw new Error("Invalid state cookie lifetime")
  }
  return { version: 1, purpose, expiresAt: now + maxAge * 1000, value }
}

/** JWE authentication is performed by the caller before this validation. */
export function readStateCookie<T>(input: unknown, purpose: string, now = Date.now()): T | undefined {
  if (!input || typeof input !== "object") return
  const envelope = input as Partial<StateCookie<T>>
  if (
    envelope.version !== 1 || envelope.purpose !== purpose ||
    !Number.isSafeInteger(envelope.expiresAt) || envelope.expiresAt! <= now
  ) return
  return envelope.value
}

export interface OAuthCallbackState {
  kind: "oauth2"
  provider: string
  state: string
  redirect: string
  codeVerifier?: string
}

export function isOAuthCallbackState(input: unknown, provider: string, state: unknown, redirect: string): input is OAuthCallbackState {
  if (!input || typeof input !== "object") return false
  const value = input as Partial<OAuthCallbackState>
  return value.kind === "oauth2" && value.provider === provider &&
    typeof value.state === "string" && value.state.length > 0 &&
    typeof state === "string" && state.length > 0 && state === value.state &&
    value.redirect === redirect
}
