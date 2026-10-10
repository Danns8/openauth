import assert from "node:assert/strict"
import { test } from "bun:test"
import { base64url, exportJWK, generateKeyPair, SignJWT, type JWTPayload } from "jose"
import { object, string } from "valibot"
import { createClient } from "../src/client.js"
import { createSubjects } from "../src/subject.js"

const origin = "https://auth.security-client.test"
const subjects = createSubjects({ user: object({ userID: string() }) })

async function fixture() {
  const { publicKey, privateKey } = await generateKeyPair("ES256")
  const key = { ...await exportJWK(publicKey), kid: "test-key", alg: "ES256", use: "sig" }
  let refreshCalls = 0
  let nextAccess = ""
  const client = createClient({
    issuer: origin,
    clientID: "web",
    fetch: async (input: string, init?: RequestInit) => {
      const url = new URL(input)
      assert.equal(url.origin, origin)
      if (url.pathname === "/.well-known/oauth-authorization-server") {
        return Response.json({ jwks_uri: origin + "/jwks" })
      }
      if (url.pathname === "/jwks") return Response.json({ keys: [key] })
      assert.equal(url.pathname, "/token")
      assert.equal(new URLSearchParams(init?.body as string).get("client_id"), "web")
      refreshCalls++
      return Response.json({ access_token: nextAccess, refresh_token: "test-refresh-next", expires_in: 60 })
    },
  })
  const mint = (overrides: JWTPayload = {}) => new SignJWT({
    iss: origin, aud: "web", sub: "user:123", exp: Math.floor(Date.now() / 1000) + 300,
    mode: "access", type: "user", properties: { userID: "123" }, ...overrides,
  }).setProtectedHeader({ alg: "ES256", kid: "test-key", typ: "JWT" }).sign(privateKey)
  return { client, mint, refreshCalls: () => refreshCalls, setNext: (access: string) => { nextAccess = access } }
}

test("SDK requires its own audience by default", async () => {
  const f = await fixture()
  assert.equal((await f.client.verify(subjects, await f.mint())).err, undefined)
  assert.ok((await f.client.verify(subjects, await f.mint({ aud: "other" }))).err)
  assert.ok((await f.client.verify(subjects, await f.mint({ aud: undefined }))).err)
})

test("SDK validates issuer, expiry, subject and subject type", async () => {
  const f = await fixture()
  for (const override of [{ iss: "https://other.test" }, { exp: undefined }, { sub: undefined }, { sub: "" }, { type: "__proto__" }, { mode: "refresh" }, { properties: { userID: 123 } }]) {
    assert.ok((await f.client.verify(subjects, await f.mint(override))).err)
  }
})

test("SDK rejects unsigned tokens", async () => {
  const f = await fixture()
  const valid = await f.mint()
  const none = base64url.encode(JSON.stringify({ alg: "none" })) + "." + valid.split(".")[1] + "."
  assert.ok((await f.client.verify(subjects, none)).err)
})

test("SDK accepts an explicit trusted resource audience, never a blanket bypass", async () => {
  const f = await fixture()
  const token = await f.mint({ aud: "resource" })
  assert.ok((await f.client.verify(subjects, token)).err)
  assert.equal((await f.client.verify(subjects, token, { audience: "resource" })).err, undefined)
})

test("automatic refresh preserves the caller's audience policy", async () => {
  const f = await fixture()
  const expired = await f.mint({ aud: "resource", exp: Math.floor(Date.now() / 1000) - 1 })
  f.setNext(await f.mint({ aud: "web" }))
  assert.ok((await f.client.verify(subjects, expired, { audience: "resource", refresh: "test-refresh" })).err)
  assert.equal(f.refreshCalls(), 1)
})

test("automatic refresh returns verified tokens with the right audience", async () => {
  const f = await fixture()
  const expired = await f.mint({ exp: Math.floor(Date.now() / 1000) - 1 })
  f.setNext(await f.mint())
  const result = await f.client.verify(subjects, expired, { refresh: "test-refresh" })
  assert.equal(result.err, undefined)
  if (result.err) throw result.err
  assert.ok(result.tokens?.access)
  assert.equal(f.refreshCalls(), 1)
})

test("an expired refresh result cannot recurse indefinitely", async () => {
  const f = await fixture()
  const expired = await f.mint({ exp: Math.floor(Date.now() / 1000) - 1 })
  f.setNext(expired)
  assert.ok((await f.client.verify(subjects, expired, { refresh: "test-refresh" })).err)
  assert.equal(f.refreshCalls(), 1)
})

test("SDK generates S256 by default and rejects insecure flow options", async () => {
  const f = await fixture()
  const result = await f.client.authorize("https://web.example.test/callback", "code")
  const url = new URL(result.url)
  assert.equal(url.searchParams.get("code_challenge_method"), "S256")
  assert.equal(result.challenge.verifier?.length, 64)
  assert.equal(url.searchParams.get("state"), result.challenge.state)
  await assert.rejects(f.client.authorize("https://web.example.test/callback", "token"))
  await assert.rejects(f.client.authorize("https://web.example.test/callback", "code", { pkce: false }))
})

test("malformed access token in refresh optimization produces a typed error", async () => {
  const f = await fixture()
  assert.ok((await f.client.refresh("test-refresh", { access: "not-a-jwt" })).err)
  assert.equal(f.refreshCalls(), 0)
})
