import assert from "node:assert/strict"
import { test } from "bun:test"
import { generatePKCE, isPKCEChallenge, isPKCEVerifier, validatePKCE } from "../src/pkce.js"
import { issuerOrigin, isOAuthCallbackState, isSafeRedirectURI, readStateCookie, registeredRedirects, stateCookie } from "../src/security.js"
import { getRelativeUrl } from "../src/util.js"

const callback = "https://web.example.test/callback"

test("PKCE matches the RFC 7636 S256 test vector", async () => {
  assert.equal(await validatePKCE(
    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    "S256",
  ), true)
})

for (const length of [43, 64, 96, 128]) {
  test(`PKCE length ${length} means characters, not bytes`, async () => {
    const proof = await generatePKCE(length)
    assert.equal(proof.verifier.length, length)
    assert.equal(proof.challenge.length, 43)
    assert.ok(isPKCEVerifier(proof.verifier))
    assert.equal(await validatePKCE(proof.verifier, proof.challenge, proof.method), true)
    assert.equal(await validatePKCE("Z".repeat(length), proof.challenge, proof.method), false)
  })
}
for (const length of [0, 42, 129, 43.5, NaN, Infinity]) {
  test(`PKCE rejects invalid length ${length}`, async () => {
    await assert.rejects(generatePKCE(length))
  })
}
for (const method of ["plain", "S512", "s256", "", null, undefined]) {
  test(`challenge validation rejects method ${String(method)}`, () => {
    assert.equal(isPKCEChallenge("a".repeat(43), method), false)
  })
}
test("PKCE rejects plain, malformed verifiers and malformed challenges", async () => {
  assert.equal(await validatePKCE("a".repeat(43), "a".repeat(43), "plain"), false)
  for (const verifier of ["", "a".repeat(42), "a".repeat(129), "!".repeat(43)]) {
    assert.equal(await validatePKCE(verifier, "a".repeat(43)), false)
  }
  assert.equal(isPKCEChallenge("a".repeat(42), "S256"), false)
  assert.equal(isPKCEChallenge("a".repeat(43) + "=", "S256"), false)
})

test("redirect registration is exact and bound to client ID", () => {
  const allowed = registeredRedirects({ web: { redirectURIs: [callback] } })
  assert.equal(allowed("web", callback), true)
  for (const uri of [callback + "/", callback + "?x=1", callback.replace("web.", "other."), callback.replace("https:", "http:"), callback.replace(".test", ".test:8443")]) {
    assert.equal(allowed("web", uri), false)
  }
  assert.equal(allowed("other", callback), false)
  assert.equal(allowed("__proto__", callback), false)
  assert.equal(registeredRedirects()("web", callback), false)
})

test("different workers.dev accounts never share redirect trust", () => {
  const allowed = registeredRedirects({ web: { redirectURIs: ["https://app.owner.workers.dev/callback"] } })
  assert.equal(allowed("web", "https://capture.attacker.workers.dev/callback"), false)
})

test("registration is snapshotted rather than mutable after startup", () => {
  const clients = { web: { redirectURIs: [callback] } }
  const allowed = registeredRedirects(clients)
  clients.web.redirectURIs.push("https://other.example.test/callback")
  assert.equal(allowed("web", "https://other.example.test/callback"), false)
})

for (const uri of ["//evil.test", "javascript:alert(1)", "data:text/html,x", "https:evil.test", "https://user:pass@evil.test/callback", callback + "#", callback + "#fragment", "https://web.example.test\\@evil.test", " https://web.example.test", "http://web.example.test/callback"]) {
  test(`reject unsafe redirect syntax ${JSON.stringify(uri)}`, () => {
    assert.equal(isSafeRedirectURI(uri), false)
    assert.throws(() => registeredRedirects({ web: { redirectURIs: [uri] } }))
  })
}

test("loopback HTTP still requires an exact registration", () => {
  for (const host of ["localhost", "127.0.0.1", "[::1]"]) {
    const uri = `http://${host}:3000/callback`
    assert.equal(isSafeRedirectURI(uri), true)
    assert.equal(registeredRedirects()("web", uri), false)
    assert.equal(registeredRedirects({ web: { redirectURIs: [uri] } })("web", uri), true)
  }
})

test("issuer accepts only a public origin, not userinfo, path or query", () => {
  assert.equal(issuerOrigin("https://auth.example.test/"), "https://auth.example.test")
  for (const uri of ["", "https://auth.example.test/path", "https://auth.example.test?x=1", "https://auth.example.test?", "https://user@auth.example.test"]) {
    assert.throws(() => issuerOrigin(uri))
  }
})

test("encrypted state requires server-side expiry and matching purpose", () => {
  const value = { state: "random-test-state" }
  const cookie = stateCookie("provider_github", 10, value, 1000)
  assert.deepEqual(readStateCookie(cookie, "provider_github", 10999), value)
  assert.equal(readStateCookie(cookie, "provider_github", 11000), undefined)
  assert.equal(readStateCookie(cookie, "provider_password", 1001), undefined)
  assert.equal(readStateCookie(value, "provider_github", 1001), undefined)
  assert.equal(readStateCookie({ ...cookie, expiresAt: Infinity }, "provider_github", 1001), undefined)
})

test("invalid state cookie lifetimes cannot silently become permanent", () => {
  for (const age of [0, -1, 0.5, Infinity, NaN, Number.MAX_SAFE_INTEGER]) {
    assert.throws(() => stateCookie("provider_github", age, {}))
  }
})

test("OAuth state binds provider, nonempty state and callback URI", () => {
  const redirect = "https://auth.example.test/github/callback"
  const value = { kind: "oauth2", provider: "github", state: "nonce", redirect }
  assert.equal(isOAuthCallbackState(value, "github", "nonce", redirect), true)
  for (const poisoned of [undefined, {}, { type: "start", redirect }, { ...value, state: "" }, { ...value, provider: "other" }, { ...value, redirect: callback }]) {
    assert.equal(isOAuthCallbackState(poisoned, "github", "nonce", redirect), false)
  }
  for (const returnedState of [undefined, null, "", "wrong"]) {
    assert.equal(isOAuthCallbackState(value, "github", returnedState, redirect), false)
  }
})

test("forwarding headers cannot rewrite issuer or upstream callback URLs", () => {
  const ctx = {
    req: { url: "https://auth.example.test/github/authorize", header: () => "evil.test" },
    get: () => undefined,
  } as unknown as Parameters<typeof getRelativeUrl>[0]
  assert.equal(getRelativeUrl(ctx, "./callback"), "https://auth.example.test/github/callback")
  const proxy = {
    req: { url: "http://internal:8787/github/authorize", header: () => "evil.test" },
    get: () => "https://auth.example.test",
  } as unknown as Parameters<typeof getRelativeUrl>[0]
  assert.equal(getRelativeUrl(proxy, "./callback"), "https://auth.example.test/github/callback")
})
