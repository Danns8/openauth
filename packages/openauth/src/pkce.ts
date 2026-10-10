function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "")
}

export function isPKCEChallenge(challenge: unknown, method: unknown): challenge is string {
  return method === "S256" && typeof challenge === "string" &&
    /^[A-Za-z0-9_-]{43}$/.test(challenge)
}

export function isPKCEVerifier(verifier: unknown): verifier is string {
  return typeof verifier === "string" && /^[A-Za-z0-9._~-]{43,128}$/.test(verifier)
}

async function generateChallenge(verifier: string) {
  const data = new TextEncoder().encode(verifier)
  const hash = await crypto.subtle.digest("SHA-256", data)
  return base64url(new Uint8Array(hash))
}

export async function generatePKCE(length: number = 64) {
  if (!Number.isInteger(length) || length < 43 || length > 128) {
    throw new Error("Code verifier length must be between 43 and 128 characters")
  }
  const buffer = crypto.getRandomValues(new Uint8Array(Math.ceil(length * 3 / 4)))
  const verifier = base64url(buffer).slice(0, length)
  const challenge = await generateChallenge(verifier)
  return { verifier, challenge, method: "S256" as const }
}

export async function validatePKCE(
  verifier: string,
  challenge: string,
  method: "S256" | "plain" = "S256",
) {
  if (!isPKCEVerifier(verifier) || !isPKCEChallenge(challenge, method)) return false
  const generated = await generateChallenge(verifier)
  let difference = 0
  for (let i = 0; i < generated.length; i++) {
    difference |= generated.charCodeAt(i) ^ challenge.charCodeAt(i)
  }
  return difference === 0
}
