import assert from "node:assert/strict"
import { test, spyOn } from "bun:test"
import { object, string } from "valibot"
import { issuer } from "../src/issuer.js"
import { createClient } from "../src/client.js"
import { createSubjects } from "../src/subject.js"
import { GithubProvider } from "../src/provider/github.js"
import { MemoryStorage } from "../src/storage/memory.js"
import { Storage } from "../src/storage/storage.js"
import { generatePKCE } from "../src/pkce.js"

const ORIGIN = "https://auth.security-issuer.test"
const CALLBACK = "https://web.security-issuer.test/callback"
const subjects = createSubjects({ user: object({ userID: string() }) })

class Cookies {
  values = new Map<string, string>()
  accept(response: Response) {
    const cookies = response.headers.getSetCookie()
    for (const cookie of cookies) {
      const pair = cookie.split(";", 1)[0]
      const at = pair.indexOf("=")
      if (at < 1) continue
      const name = pair.slice(0, at)
      if (/max-age=0(?:;|$)/i.test(cookie)) this.values.delete(name)
      else this.values.set(name, pair.slice(at + 1))
    }
  }
  header() { return [...this.values].map(([name, value]) => `${name}=${value}`).join("; ") }
}

function fixture(options: { noRegistration?: boolean; allow?: () => Promise<boolean> } = {}) {
  const storage = MemoryStorage()
  const app = issuer({
    issuer: ORIGIN,
    storage,
    subjects,
    clients: options.noRegistration ? undefined : {
      web: { redirectURIs: [CALLBACK] },
      other: { redirectURIs: [CALLBACK] },
    },
    allow: options.allow,
    providers: {
      // Test-only providers: never deploy these.
      dummy: { type: "dummy", init(route, ctx) {
        route.get("/authorize", (c) => ctx.success(c, { email: "test@example.test" }))
      } },
      password: { type: "password-test", init(route, ctx) {
        route.get("/change", async (c) => {
          await ctx.set(c, "provider", 600, { type: "start", redirect: ORIGIN + "/github/callback" })
          return c.text("test state")
        })
      } },
      github: GithubProvider({ clientID: "test-only", clientSecret: "not-a-real-secret", scopes: [] }),
    },
    success: async (ctx) => ctx.subject("user", { userID: "123" }),
  })
  const client = createClient({ issuer: ORIGIN, clientID: "web", fetch: (url, init) => Promise.resolve(app.request(url, init)) })
  const request = async (path: string, init: RequestInit = {}, jar?: Cookies) => {
    const headers = new Headers(init.headers)
    if (jar) headers.set("cookie", jar.header())
    const response = await app.request(new URL(path, ORIGIN), { ...init, headers })
    jar?.accept(response)
    return response
  }
  const post = (fields: Record<string, string>) => request("/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields),
  })
  const authorization = async () => {
    const result = await client.authorize(CALLBACK, "code", { provider: "dummy" })
    return { ...result, url: new URL(result.url) }
  }
  const grant = async () => {
    const start = await authorization()
    const jar = new Cookies()
    let response = await request(start.url.toString(), {}, jar)
    assert.equal(response.status, 302)
    response = await request(response.headers.get("location")!, {}, jar)
    assert.equal(response.status, 302)
    const callback = new URL(response.headers.get("location")!)
    assert.equal(callback.searchParams.get("state"), start.challenge.state)
    return { code: callback.searchParams.get("code")!, verifier: start.challenge.verifier!, jar }
  }
  return { app, client, storage, request, post, authorization, grant }
}

test("issuer defaults to deny without registrations or an explicit policy", async () => {
  const f = fixture({ noRegistration: true })
  const start = await f.authorization()
  const response = await f.request(start.url.toString())
  assert.equal(response.status, 400)
  assert.equal(response.headers.get("location"), null)
})

test("denied redirect is never used by error handling, even with allow=true", async () => {
  const f = fixture({ allow: async () => true })
  const start = await f.authorization()
  start.url.searchParams.set("redirect_uri", "https://outside.invalid/capture")
  const response = await f.request(start.url.toString())
  assert.equal(response.status, 400)
  assert.equal(response.headers.get("location"), null)
})

for (const provider of ["/outside.invalid", "unknown", "__proto__", "constructor"]) {
  test(`issuer rejects unregistered provider ${provider}`, async () => {
    const f = fixture()
    const start = await f.authorization()
    start.url.searchParams.set("provider", provider)
    const response = await f.request(start.url.toString())
    assert.equal(response.status, 400)
    assert.equal(response.headers.get("location"), null)
  })
}

for (const mutation of ["missing-challenge", "missing-method", "plain", "unknown-method", "duplicate", "implicit"]) {
  test(`issuer rejects ${mutation} authorization requests`, async () => {
    const f = fixture()
    const start = await f.authorization()
    const params = start.url.searchParams
    if (mutation === "missing-challenge") params.delete("code_challenge")
    if (mutation === "missing-method") params.delete("code_challenge_method")
    if (mutation === "plain") params.set("code_challenge_method", "plain")
    if (mutation === "unknown-method") params.set("code_challenge_method", "S512")
    if (mutation === "duplicate") params.append("client_id", "other")
    if (mutation === "implicit") params.set("response_type", "token")
    const response = await f.request(start.url.toString())
    assert.equal(response.status, 400)
    assert.equal(response.headers.get("location"), null)
  })
}

test("correct code+PKCE succeeds, failed proof does not consume the code", async () => {
  const f = fixture()
  const grant = await f.grant()
  const fields = { grant_type: "authorization_code", code: grant.code, client_id: "web", redirect_uri: CALLBACK, code_verifier: "Z".repeat(64) }
  assert.equal((await f.post(fields)).status, 400)
  const response = await f.post({ ...fields, code_verifier: grant.verifier })
  assert.equal(response.status, 200)
  assert.equal(response.headers.get("cache-control"), "no-store")
  const tokens = await response.json()
  assert.equal(tokens.token_type, "Bearer")
  assert.equal((await f.client.verify(subjects, tokens.access_token)).err, undefined)
  assert.equal((await f.post({ ...fields, code_verifier: grant.verifier })).status, 400)
})

test("refresh is bound to the issuing client before any rotation", async () => {
  const f = fixture()
  const grant = await f.grant()
  const result = await f.client.exchange(grant.code, CALLBACK, grant.verifier)
  if (result.err) throw result.err
  const fields = { grant_type: "refresh_token", refresh_token: result.tokens.refresh }
  assert.equal((await f.post(fields)).status, 400)
  assert.equal((await f.post({ ...fields, client_id: "other" })).status, 400)
  assert.equal((await f.post({ ...fields, client_id: "web" })).status, 200)
})

test("authorization code expiry is checked even if a storage adapter returns stale data", async () => {
  const f = fixture()
  const proof = await generatePKCE()
  await Storage.set(f.storage, ["oauth:code", "expired-test-code"], {
    type: "user", properties: { userID: "123" }, subject: "user:123", clientID: "web",
    redirectURI: CALLBACK, pkce: { challenge: proof.challenge, method: "S256" },
    expiresAt: Date.now() - 1, ttl: { access: 60, refresh: 600 },
  }, 60)
  const response = await f.post({ grant_type: "authorization_code", code: "expired-test-code", redirect_uri: CALLBACK, client_id: "web", code_verifier: proof.verifier })
  assert.equal(response.status, 400)
})

test("metadata and callback construction ignore forwarded hosts", async () => {
  const f = fixture()
  const response = await f.request("/.well-known/oauth-authorization-server", {
    headers: { "x-forwarded-host": "outside.invalid", "x-forwarded-proto": "http" },
  })
  const metadata = await response.json()
  assert.equal(metadata.issuer, ORIGIN)
  assert.deepEqual(metadata.response_types_supported, ["code"])
  assert.deepEqual(metadata.code_challenge_methods_supported, ["S256"])
})

test("Password state cannot substitute for GitHub OAuth state", async () => {
  const f = fixture()
  const jar = new Cookies()
  await f.request("/password/change", {}, jar)
  let upstreamCalls = 0
  const network = spyOn(globalThis, "fetch").mockImplementation(async () => {
    upstreamCalls++
    throw new Error("Unexpected upstream request")
  })
  try {
    const response = await f.request("/github/callback?code=test-only-code&state=wrong", {}, jar)
    assert.equal(response.status, 400)
    assert.equal(upstreamCalls, 0)
  } finally { network.mockRestore() }
})

test("valid upstream OAuth state succeeds with a mocked token endpoint", async () => {
  const f = fixture()
  const jar = new Cookies()
  const start = await f.client.authorize(CALLBACK, "code", { provider: "github" })
  let response = await f.request(start.url, {}, jar)
  response = await f.request(response.headers.get("location")!, {}, jar)
  const upstreamURL = new URL(response.headers.get("location")!)
  const state = upstreamURL.searchParams.get("state")!
  let calls = 0
  const network = spyOn(globalThis, "fetch").mockImplementation(async (url, init) => {
    assert.equal(String(url), "https://github.com/login/oauth/access_token")
    assert.equal(new URLSearchParams(init?.body as string).get("redirect_uri"), ORIGIN + "/github/callback")
    calls++
    return Response.json({ access_token: "test-upstream-token", token_type: "bearer" })
  })
  try {
    response = await f.request("/github/callback?" + new URLSearchParams({ state, code: "test-only-code" }), {}, jar)
    assert.equal(response.status, 302)
    assert.ok(new URL(response.headers.get("location")!).searchParams.get("code"))
    assert.equal(calls, 1)
    assert.equal(jar.values.has("provider_github"), false)
  } finally { network.mockRestore() }
})

test("invalid grant requests remain local JSON errors", async () => {
  const f = fixture()
  const response = await f.post({ grant_type: "unsupported" })
  assert.equal(response.status, 400)
  assert.equal(response.headers.get("location"), null)
  assert.equal(response.headers.get("cache-control"), "no-store")
  assert.equal((await response.json()).error, "unsupported_grant_type")
})
