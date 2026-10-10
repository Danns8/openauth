# OAuth security hardening: phase 1

This change hardens the client, authorization endpoint and OAuth provider boundary.
It is **not** a complete remediation of the storage and password-recovery audit.
Review the remaining work below before production deployment.

## Breaking changes and rollout

Deploy the issuer and its SDK consumers together in a staging environment first.
Existing access tokens still need to satisfy the new audience and required-claim
checks. Existing refresh tokens require their original `client_id` on refresh.
In-flight authorization codes and old-format login/provider cookies are rejected;
users with an in-progress login or password recovery must restart that flow.
No changes are made to the KV namespace or to deployed infrastructure by this commit.

### Register exact redirect URIs

The previous hostname-grouping and unconditional localhost defaults are removed.
With neither `clients` nor a custom `allow` policy, authorization is denied.

Merge these options into your existing, fully configured issuer:

```ts
issuer({
  issuer: "https://auth.example.com",
  clients: {
    web: { redirectURIs: ["https://web.example.com/auth/callback"] },
    spa: { redirectURIs: ["https://app.example.com/auth/callback"] },
  },
  providers,
  storage,
  subjects,
  success,
})
```

Registrations compare the original URI strings exactly, including scheme, port,
path and query. They do not support wildcards. HTTP is accepted only for explicitly
registered loopback development callbacks. URI fragments and userinfo are rejected.
Use separate client IDs for independently trusted applications.

A custom `allow` callback remains available for dynamic registration stores. When
`clients` is also supplied, both checks must pass. Without `clients`, the callback
is responsible for checking the full redirect URI against that client's registered
URIs. It must be safe to invoke more than once. Do not use `isDomainMatch` or return
true for every request as a production authorization policy.

### Configure the public issuer origin

`issuer.issuer` specifies a fixed public origin, without a base path, query or
fragment. If omitted, the actual request URL supplies the origin. The library no
longer trusts `x-forwarded-host`, `x-forwarded-proto` or `x-forwarded-port`.
Configure the public origin explicitly when a reverse proxy supplies an internal
request URL. Both the hostname and the internal port are replaced when doing so.

### Use authorization code flow with S256 PKCE

`client.authorize(redirectURI, "code")` now generates PKCE by default. Passing
`pkce: false`, requesting the implicit `token` response, a partial PKCE parameter
pair, or any challenge method other than `S256` is rejected. The verifier must have
43-128 RFC 7636 unreserved characters; `generatePKCE(length)` now treats length as
characters rather than random bytes. The default generated verifier is 64 characters.

```ts
const { challenge, url } = await client.authorize(redirectURI, "code")
// Persist challenge in the app's login transaction before redirecting to url.
// In the callback, retrieve and consume that transaction, and check state first.
if (!savedChallenge || returnedState !== savedChallenge.state) {
  throw new Error("Invalid login state")
}
const exchanged = await client.exchange(code, redirectURI, savedChallenge.verifier)
```

Use server-side session storage for server-side web clients. A SPA may use
per-tab session storage for its short-lived login transaction; this is not a
recommendation to put long-lived refresh tokens in JavaScript-readable storage.
The SDK does not replace the application's state comparison or transaction storage.

### Audience and refresh checks

`client.verify()` requires the issuer, audience, expiry and subject claims. The
expected audience defaults to `clientID`; accepted signing algorithms are ES256
and the project's legacy RS512. Unknown subject types are rejected before schema
lookup. One automatic refresh is allowed, and its result is verified with the
same audience policy without a recursive refresh loop.

A shared resource server may set a **trusted** `verify(..., { audience })` value.
Never derive it from request parameters or from the token being verified.
This override does not change the client bound to a refresh token.

The SDK now sends `client_id` when refreshing; the issuer compares it with the
stored client before changing refresh state. This is client binding, **not**
confidential-client authentication. Raw HTTP integrations must add this parameter.

All token responses include `token_type: "Bearer"` and use `Cache-Control: no-store`
and `Pragma: no-cache`. Unknown grants return local OAuth JSON errors, never a
redirect taken from a browser cookie.

### Provider cookies and callbacks

Provider cookies are named per configured provider, and their encrypted payloads
include the cookie purpose and an absolute expiry. Payloads in the old format,
expired payloads and payloads copied between provider cookie names are rejected.
The authorization transaction cookie expires after ten minutes.

OAuth callbacks require a matching provider, nonempty state and exact callback
URI, including on error responses. Duplicate callback parameters are rejected.
The provider's extra `query` options can no longer overwrite security parameters
such as state, client ID, redirect URI, response type, scope or PKCE. Move scopes
to `scopes` and keep non-protocol options such as `prompt` in `query`.
A successful upstream exchange clears the provider cookie.

Cookie expiry and deletion do **not** make a transaction single-use. Password
recovery and other stateful transactions still need a server-side authoritative
record; the remaining work below is intentional, not considered fixed here.

## Remaining security work

- Password recovery needs server-side attempt budgets, fixed transaction deadlines
  and atomic, single-use completion. The Password provider's own return URL and
  form CSRF controls also need remediation. This commit must not be presented as
  resolving the password-reset finding.
- Authorization-code consumption remains a non-atomic get/delete sequence. An
  explicit `expiresAt` prevents use past the code deadline, but does not solve
  concurrent redemption or stale deletion visibility.
- Refresh rotation still needs an authoritative token-family model, retained replay
  evidence and atomic revocation. Requiring `client_id` does not solve replay.
- Cloudflare KV is not turned into a transactional store by this patch. Adopt an
  appropriate authoritative transactional design, such as a correctly implemented
  Durable Object, for these security-critical operations and reads.
- The issuer now passes the actual selected subject to a provider's invalidation
  callback, but registration-to-account association and full password-change
  revocation still need lifecycle work.
- Active signing/encryption key selection avoids expired keys. Live JWKS refresh,
  bounded caches, old-key overlap and cookie key-ring rotation remain to be done.
- Generic storage TTL semantics, confidential-client authentication, the deployment
  password policy/rate limits, UI security headers and the locked production
  dependency audit are not completed by this change.

## Validation

New suites cover protocol primitives, SDK validation and local Hono request flows.
The GitHub OAuth success test mocks only the upstream token endpoint and uses test
credentials; it does not contact GitHub or any production deployment.

```sh
bun install
cd packages/openauth
bun run build
bun test
```

During authoring, 37 primitive tests were run against the actual changed modules
under Node.js 22.16.0 after TypeScript transpilation, with only the test-runner import
changed from `bun:test` to `node:test`; all passed. The PKCE and security helper
modules also passed a strict standalone TypeScript check. Syntax checks cover the
other changed TypeScript files. This is not a full project type check or a Bun,
Workers, browser, KV or real-provider integration result. The author's environment
has no Bun and cannot install repository dependencies. Run the full build/test
suite and the Cloudflare staging checks before merging and deployment.
