/**
 * The `issuer` create an OpentAuth server, a [Hono](https://hono.dev) app that's
 * designed to run anywhere.
 *
 * The `issuer` function requires a few things:
 *
 * ```ts title="issuer.ts"
 * import { issuer } from "@openauthjs/openauth"
 *
 * const app = issuer({
 *   providers: { ... },
 *   storage,
 *   subjects,
 *   success: async (ctx, value) => { ... }
 * })
 * ```
 *
 * #### Add providers
 *
 * You start by specifying the auth providers you are going to use. Let's say you want your users
 * to be able to authenticate with GitHub and with their email and password.
 *
 * ```ts title="issuer.ts"
 * import { GithubProvider } from "@openauthjs/openauth/provider/github"
 * import { PasswordProvider } from "@openauthjs/openauth/provider/password"
 *
 * const app = issuer({
 *   providers: {
 *     github: GithubProvider({
 *       // ...
 *     }),
 *     password: PasswordProvider({
 *       // ...
 *     }),
 *   },
 * })
 * ```
 *
 * #### Handle success
 *
 * The `success` callback receives the payload when a user completes a provider's auth flow.
 *
 * ```ts title="issuer.ts"
 * const app = issuer({
 *   providers: { ... },
 *   subjects,
 *   async success(ctx, value) {
 *     let userID
 *     if (value.provider === "password") {
 *       console.log(value.email)
 *       userID = ... // lookup user or create them
 *     }
 *     if (value.provider === "github") {
 *       console.log(value.tokenset.access)
 *       userID = ... // lookup user or create them
 *     }
 *     return ctx.subject("user", {
 *       userID
 *     })
 *   }
 * })
 * ```
 *
 * Once complete, the `issuer` issues the access tokens that a client can use. The `ctx.subject`
 * call is what is placed in the access token as a JWT.
 *
 * #### Define subjects
 *
 * You define the shape of these in the `subjects` field.
 *
 * ```ts title="subjects.ts"
 * import { object, string } from "valibot"
 * import { createSubjects } from "@openauthjs/openauth/subject"
 *
 * const subjects = createSubjects({
 *   user: object({
 *     userID: string()
 *   })
 * })
 * ```
 *
 * It's good to place this in a separate file since this'll be used in your client apps as well.
 *
 * ```ts title="issuer.ts"
 * import { subjects } from "./subjects.js"
 *
 * const app = issuer({
 *   providers: { ... },
 *   subjects,
 *   // ...
 * })
 * ```
 *
 * #### Deploy
 *
 * Since `issuer` is a Hono app, you can deploy it anywhere Hono supports.
 *
 * <Tabs>
 *   <TabItem label="Node">
 *   ```ts title="issuer.ts"
 *   import { serve } from "@hono/node-server"
 *
 *   serve(app)
 *   ```
 *   </TabItem>
 *   <TabItem label="Lambda">
 *   ```ts title="issuer.ts"
 *   import { handle } from "hono/aws-lambda"
 *
 *   export const handler = handle(app)
 *   ```
 *   </TabItem>
 *   <TabItem label="Bun">
 *   ```ts title="issuer.ts"
 *   export default app
 *   ```
 *   </TabItem>
 *   <TabItem label="Workers">
 *   ```ts title="issuer.ts"
 *   export default app
 *   ```
 *   </TabItem>
 * </Tabs>
 *
 * @packageDocumentation
 */
import { Provider, ProviderOptions } from "./provider/provider.js"
import { SubjectPayload, SubjectSchema } from "./subject.js"
import { Hono } from "hono/tiny"
import { handle as awsHandle } from "hono/aws-lambda"
import { Context } from "hono"
import { deleteCookie, getCookie, setCookie } from "hono/cookie"
import type { v1 } from "@standard-schema/spec"

/**
 * Sets the subject payload in the JWT token and returns the response.
 *
 * ```ts
 * ctx.subject("user", {
 *   userID
 * })
 * ```
 */
export interface OnSuccessResponder<
  T extends { type: string; properties: any },
> {
  /**
   * The `type` is the type of the subject, that was defined in the `subjects` field.
   *
   * The `properties` are the properties of the subject. This is the shape of the subject that
   * you defined in the `subjects` field.
   */
  subject<Type extends T["type"]>(
    type: Type,
    properties: Extract<T, { type: Type }>["properties"],
    opts?: {
      ttl?: {
        access?: number
        refresh?: number
      }
      subject?: string
    },
  ): Promise<Response>
}

/**
 * @internal
 */
export interface AuthorizationState {
  redirect_uri: string
  response_type: string
  state: string
  client_id: string
  audience?: string
  pkce?: {
    challenge: string
    method: "S256"
  }
}

/**
 * @internal
 */
export type Prettify<T> = {
  [K in keyof T]: T[K]
} & {}

import {
  OauthError,
  UnknownStateError,
} from "./error.js"
import { compactDecrypt, CompactEncrypt, jwtVerify, SignJWT } from "jose"
import { Storage, StorageAdapter } from "./storage/storage.js"
import { encryptionKeys, legacySigningKeys, signingKeys } from "./keys.js"
import { isPKCEChallenge, validatePKCE } from "./pkce.js"
import { issuerOrigin, isSafeRedirectURI, registeredRedirects, stateCookie, readStateCookie, type RegisteredClients } from "./security.js"
import { Select } from "./ui/select.js"
import { setTheme, Theme } from "./ui/theme.js"
import { getRelativeUrl, lazy } from "./util.js"
import { DynamoStorage } from "./storage/dynamo.js"
import { MemoryStorage } from "./storage/memory.js"
import { cors } from "hono/cors"
import { logger } from "hono/logger"

/** @internal */
export const aws = awsHandle

export interface IssuerInput<
  Providers extends Record<string, Provider<any>>,
  Subjects extends SubjectSchema,
  Result = {
    [key in keyof Providers]: Prettify<
      {
        provider: key
      } & (Providers[key] extends Provider<infer T> ? T : {})
    >
  }[keyof Providers],
> {
  /**
   * The shape of the subjects that you want to return.
   *
   * @example
   *
   * ```ts title="issuer.ts"
   * import { object, string } from "valibot"
   * import { createSubjects } from "@openauthjs/openauth/subject"
   *
   * issuer({
   *   subjects: createSubjects({
   *     user: object({
   *       userID: string()
   *     })
   *   })
   *   // ...
   * })
   * ```
   */
  subjects: Subjects
  /**
   * The storage adapter that you want to use.
   *
   * @example
   * ```ts title="issuer.ts"
   * import { DynamoStorage } from "@openauthjs/openauth/storage/dynamo"
   *
   * issuer({
   *   storage: DynamoStorage()
   *   // ...
   * })
   * ```
   */
  storage?: StorageAdapter
  /** Fixed public origin. Required when the request URL is an internal proxy URL. */
  issuer?: string
  /** Exact redirect URI registrations. Unknown clients are denied by default. */
  clients?: RegisteredClients
  /**
   * The providers that you want your OpenAuth server to support.
   *
   * @example
   *
   * ```ts title="issuer.ts"
   * import { GithubProvider } from "@openauthjs/openauth/provider/github"
   *
   * issuer({
   *   providers: {
   *     github: GithubProvider()
   *   }
   * })
   * ```
   *
   * The key is just a string that you can use to identify the provider. It's passed back to
   * the `success` callback.
   *
   * You can also specify multiple providers.
   *
   * ```ts
   * {
   *   providers: {
   *     github: GithubProvider(),
   *     google: GoogleProvider()
   *   }
   * }
   * ```
   */
  providers: Providers
  /**
   * The theme you want to use for the UI.
   *
   * This includes the UI the user sees when selecting a provider. And the `PasswordUI` and
   * `CodeUI` that are used by the `PasswordProvider` and `CodeProvider`.
   *
   * @example
   * ```ts title="issuer.ts"
   * import { THEME_SST } from "@openauthjs/openauth/ui/theme"
   *
   * issuer({
   *   theme: THEME_SST
   *   // ...
   * })
   * ```
   *
   * Or define your own.
   *
   * ```ts title="issuer.ts"
   * import type { Theme } from "@openauthjs/openauth/ui/theme"
   *
   * const MY_THEME: Theme = {
   *   // ...
   * }
   *
   * issuer({
   *   theme: MY_THEME
   *   // ...
   * })
   * ```
   */
  theme?: Theme
  /**
   * Set the TTL, in seconds, for access and refresh tokens.
   *
   * @example
   * ```ts
   * {
   *   ttl: {
   *     access: 60 * 60 * 24 * 30,
   *     refresh: 60 * 60 * 24 * 365
   *   }
   * }
   * ```
   */
  ttl?: {
    /**
     * Interval in seconds where the access token is valid.
     * @default 30d
     */
    access?: number
    /**
     * Interval in seconds where the refresh token is valid.
     * @default 1y
     */
    refresh?: number
    /**
     * Interval in seconds where refresh token reuse is allowed. This helps mitigrate
     * concurrency issues.
     * @default 60s
     */
    reuse?: number
    /**
     * Interval in seconds to retain refresh tokens for reuse detection.
     * @default 0s
     */
    retention?: number
  }
  /**
   * Optionally, configure the UI that's displayed when the user visits the root URL of the
   * of the OpenAuth server.
   *
   * ```ts title="issuer.ts"
   * import { Select } from "@openauthjs/openauth/ui/select"
   *
   * issuer({
   *   select: Select({
   *     providers: {
   *       github: { hide: true },
   *       google: { display: "Google" }
   *     }
   *   })
   *   // ...
   * })
   * ```
   *
   * @default Select()
   */
  select?(providers: Record<string, string>, req: Request): Promise<Response>
  /**
   * @internal
   */
  start?(req: Request): Promise<void>
  /**
   * The success callback that's called when the user completes the flow.
   *
   * This is called after the user has been redirected back to your app after the OAuth flow.
   *
   * @example
   * ```ts
   * {
   *   success: async (ctx, value) => {
   *     let userID
   *     if (value.provider === "password") {
   *       console.log(value.email)
   *       userID = ... // lookup user or create them
   *     }
   *     if (value.provider === "github") {
   *       console.log(value.tokenset.access)
   *       userID = ... // lookup user or create them
   *     }
   *     return ctx.subject("user", {
   *       userID
   *     })
   *   },
   *   // ...
   * }
   * ```
   */
  success(
    response: OnSuccessResponder<SubjectPayload<Subjects>>,
    input: Result,
    req: Request,
  ): Promise<Response>
  /**
   * @internal
   */
  error?(error: UnknownStateError, req: Request): Promise<Response>
  /**
   * Additional authorization policy. When `clients` is provided, this callback
   * cannot override its exact redirect URI registrations. Without `clients`, this
   * callback MUST validate both the client ID and its full registered redirect URI.
   * With neither option configured, authorization requests are denied.
   * The callback must be safe to call again when completing an authorization.
   */
  allow?(
    input: {
      clientID: string
      redirectURI: string
      audience?: string
    },
    req: Request,
  ): Promise<boolean>
}

/**
 * Create an OpenAuth server, a Hono app.
 */
export function issuer<
  Providers extends Record<string, Provider<any>>,
  Subjects extends SubjectSchema,
  Result = {
    [key in keyof Providers]: Prettify<
      {
        provider: key
      } & (Providers[key] extends Provider<infer T> ? T : {})
    >
  }[keyof Providers],
>(input: IssuerInput<Providers, Subjects, Result>) {
  const error =
    input.error ??
    function (err) {
      return new Response(err.message, {
        status: 400,
        headers: {
          "Content-Type": "text/plain",
        },
      })
    }
  const ttlAccess = input.ttl?.access ?? 60 * 60 * 24 * 30
  const ttlRefresh = input.ttl?.refresh ?? 60 * 60 * 24 * 365
  const ttlRefreshReuse = input.ttl?.reuse ?? 60
  const ttlRefreshRetention = input.ttl?.retention ?? 0
  if (input.theme) {
    setTheme(input.theme)
  }

  const select = lazy(() => input.select ?? Select())
  const configuredIssuer = input.issuer !== undefined ? issuerOrigin(input.issuer) : undefined
  const registered = registeredRedirects(input.clients)
  async function allowAuthorization(value: AuthorizationState, req: Request) {
    if (!isSafeRedirectURI(value.redirect_uri)) return false
    if (input.clients && !registered(value.client_id, value.redirect_uri)) return false
    if (input.allow) {
      return input.allow({
        clientID: value.client_id,
        redirectURI: value.redirect_uri,
        audience: value.audience,
      }, req)
    }
    return registered(value.client_id, value.redirect_uri)
  }

  let storage = input.storage
  if (process.env.OPENAUTH_STORAGE) {
    const parsed = JSON.parse(process.env.OPENAUTH_STORAGE)
    if (parsed.type === "dynamo") storage = DynamoStorage(parsed.options)
    if (parsed.type === "memory") storage = MemoryStorage()
    if (parsed.type === "cloudflare")
      throw new Error(
        "Cloudflare storage cannot be configured through env because it requires bindings.",
      )
  }
  if (!storage)
    throw new Error(
      "Store is not configured. Either set the `storage` option or set `OPENAUTH_STORAGE` environment variable.",
    )
  const allSigning = lazy(() =>
    Promise.all([signingKeys(storage), legacySigningKeys(storage)]).then(
      ([a, b]) => [...a, ...b],
    ),
  )
  const allEncryption = lazy(() => encryptionKeys(storage))
  const signingKey = lazy(() => allSigning().then((all) => all.find((key) => !key.expired)!))
  const encryptionKey = lazy(() => allEncryption().then((all) => all.find((key) => !key.expired)!))

  const auth: Omit<ProviderOptions<any>, "name"> = {
    async success(ctx: Context, properties: any, successOpts) {
      return await input.success(
        {
          async subject(type, properties, subjectOpts) {
            const authorization = await getAuthorization(ctx)
            const subject = subjectOpts?.subject
              ? subjectOpts.subject
              : await resolveSubject(type, properties)
            await successOpts?.invalidate?.(subject)
            if (authorization.response_type === "code") {
              const code = crypto.randomUUID()
              await Storage.set(
                storage,
                ["oauth:code", code],
                {
                  type,
                  properties,
                  subject,
                  redirectURI: authorization.redirect_uri,
                  clientID: authorization.client_id,
                  pkce: authorization.pkce,
                  expiresAt: Date.now() + 60 * 1000,
                  ttl: {
                    access: subjectOpts?.ttl?.access ?? ttlAccess,
                    refresh: subjectOpts?.ttl?.refresh ?? ttlRefresh,
                  },
                },
                60,
              )
              const location = new URL(authorization.redirect_uri)
              location.searchParams.set("code", code)
              location.searchParams.set("state", authorization.state || "")
              await auth.unset(ctx, "authorization")
              return ctx.redirect(location.toString(), 302)
            }
            throw new OauthError(
              "invalid_request",
              `Unsupported response_type: ${authorization.response_type}`,
            )
          },
        },
        {
          provider: ctx.get("provider"),
          ...properties,
        },
        ctx.req.raw,
      )
    },
    forward(ctx, response) {
      return ctx.newResponse(
        response.body,
        response.status as any,
        Object.fromEntries(response.headers.entries()),
      )
    },
    async set(ctx, key, maxAge, value) {
      const name = cookieName(ctx, key)
      setCookie(ctx, name, await encrypt(stateCookie(name, maxAge, value)), {
        maxAge,
        path: "/",
        httpOnly: true,
        ...(getRelativeUrl(ctx, "/").startsWith("https://")
          ? { secure: true, sameSite: "None" as const }
          : { sameSite: "Lax" as const }),
      })
    },
    async get(ctx: Context, key: string) {
      const name = cookieName(ctx, key)
      const raw = getCookie(ctx, name)
      if (!raw) return
      try {
        return readStateCookie<any>(await decrypt(raw), name)
      } catch {
        // Invalid or old-format cookies are not authorization credentials.
        return undefined
      }
    },
    async unset(ctx: Context, key: string) {
      deleteCookie(ctx, cookieName(ctx, key), { path: "/" })
    },
    async invalidate(subject: string) {
      // Resolve the scan in case modifications interfere with iteration
      const keys = await Array.fromAsync(
        Storage.scan(this.storage, ["oauth:refresh", subject]),
      )
      for (const [key] of keys) {
        await Storage.remove(this.storage, key)
      }
    },
    storage,
  }

  function cookieName(ctx: Context, key: string) {
    if (key !== "provider") return key
    const provider = ctx.get("provider") as string | undefined
    if (!provider || !/^[A-Za-z0-9_-]+$/.test(provider)) throw new UnknownStateError()
    return `provider_${provider}`
  }

  async function getAuthorization(ctx: Context): Promise<AuthorizationState> {
    const match = ctx.get("authorization") || await auth.get(ctx, "authorization")
    if (
      !match || match.response_type !== "code" ||
      typeof match.client_id !== "string" || !match.client_id ||
      typeof match.state !== "string" ||
      !isPKCEChallenge(match.pkce?.challenge, match.pkce?.method) ||
      !(await allowAuthorization(match, ctx.req.raw))
    ) throw new UnknownStateError()
    return match
  }

  async function encrypt(value: any) {
    return await new CompactEncrypt(
      new TextEncoder().encode(JSON.stringify(value)),
    )
      .setProtectedHeader({ alg: "RSA-OAEP-512", enc: "A256GCM" })
      .encrypt(await encryptionKey().then((k) => k.public))
  }

  async function resolveSubject(type: string, properties: any) {
    const jsonString = JSON.stringify(properties)
    const encoder = new TextEncoder()
    const data = encoder.encode(jsonString)
    const hashBuffer = await crypto.subtle.digest("SHA-1", data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashHex = hashArray
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
    return `${type}:${hashHex.slice(0, 16)}`
  }

  async function generateTokens(
    ctx: Context,
    value: {
      type: string
      properties: any
      subject: string
      clientID: string
      ttl: {
        access: number
        refresh: number
      }
      timeUsed?: number
      nextToken?: string
    },
    opts?: {
      generateRefreshToken?: boolean
    },
  ) {
    const refreshToken = value.nextToken ?? crypto.randomUUID()
    if (opts?.generateRefreshToken ?? true) {
      /**
       * Generate and store the next refresh token after the one we are currently returning.
       * Reserving these in advance avoids concurrency issues with multiple refreshes.
       * Similar treatment should be given to any other values that may have race conditions,
       * for example if a jti claim was added to the access token.
       */
      const refreshValue = {
        ...value,
        nextToken: crypto.randomUUID(),
      }
      delete refreshValue.timeUsed
      await Storage.set(
        storage!,
        ["oauth:refresh", value.subject, refreshToken],
        refreshValue,
        value.ttl.refresh,
      )
    }
    const accessTimeUsed = Math.floor((value.timeUsed ?? Date.now()) / 1000)
    return {
      access: await new SignJWT({
        mode: "access",
        type: value.type,
        properties: value.properties,
        aud: value.clientID,
        iss: issuer(ctx),
        sub: value.subject,
      })
        .setExpirationTime(Math.floor(accessTimeUsed + value.ttl.access))
        .setProtectedHeader(
          await signingKey().then((k) => ({
            alg: k.alg,
            kid: k.id,
            typ: "JWT",
          })),
        )
        .sign(await signingKey().then((item) => item.private)),
      expiresIn: Math.floor(
        accessTimeUsed + value.ttl.access - Date.now() / 1000,
      ),
      refresh: [value.subject, refreshToken].join(":"),
    }
  }

  async function decrypt(value: string) {
    return JSON.parse(
      new TextDecoder().decode(
        await compactDecrypt(
          value,
          await encryptionKey().then((v) => v.private),
        ).then((value) => value.plaintext),
      ),
    )
  }

  function issuer(ctx: Context) {
    return new URL(getRelativeUrl(ctx, "/")).origin
  }

  const app = new Hono<{
    Variables: {
      authorization: AuthorizationState
      openauthIssuer: string
    }
  }>().use(logger())
  app.use(async (c, next) => {
    if (configuredIssuer) c.set("openauthIssuer", configuredIssuer)
    await next()
  })
  app.use("/token", async (c, next) => {
    c.header("Cache-Control", "no-store")
    c.header("Pragma", "no-cache")
    await next()
  })

  for (const [name, value] of Object.entries(input.providers)) {
    if (!/^[A-Za-z0-9_-]+$/.test(name)) throw new Error("Invalid provider name")
    const route = new Hono<any>()
    route.use(async (c, next) => {
      c.set("provider", name)
      await next()
    })
    value.init(route, {
      name,
      ...auth,
    })
    app.route(`/${name}`, route)
  }

  app.get(
    "/.well-known/jwks.json",
    cors({
      origin: "*",
      allowHeaders: ["*"],
      allowMethods: ["GET"],
      credentials: false,
    }),
    async (c) => {
      const all = await allSigning()
      return c.json({
        keys: all.map((item) => ({
          ...item.jwk,
          alg: item.alg,
          exp: item.expired
            ? Math.floor(item.expired.getTime() / 1000)
            : undefined,
        })),
      })
    },
  )

  app.get(
    "/.well-known/oauth-authorization-server",
    cors({
      origin: "*",
      allowHeaders: ["*"],
      allowMethods: ["GET"],
      credentials: false,
    }),
    async (c) => {
      const iss = issuer(c)
      return c.json({
        issuer: iss,
        authorization_endpoint: `${iss}/authorize`,
        token_endpoint: `${iss}/token`,
        jwks_uri: `${iss}/.well-known/jwks.json`,
        response_types_supported: ["code"],
        code_challenge_methods_supported: ["S256"],
      })
    },
  )

  app.post(
    "/token",
    cors({
      origin: "*",
      allowHeaders: ["*"],
      allowMethods: ["POST"],
      credentials: false,
    }),
    async (c) => {
      const form = await c.req.formData()
      for (const name of ["grant_type", "code", "redirect_uri", "client_id", "code_verifier", "refresh_token", "provider", "client_secret"]) {
        const values = form.getAll(name)
        if (values.length > 1 || values.some((value) => typeof value !== "string")) {
          return c.json({ error: "invalid_request", error_description: `Invalid ${name}` }, 400)
        }
      }
      const grantType = form.get("grant_type")

      if (grantType === "authorization_code") {
        const code = form.get("code")
        if (!code)
          return c.json(
            {
              error: "invalid_request",
              error_description: "Missing code",
            },
            400,
          )
        const key = ["oauth:code", code.toString()]
        const payload = await Storage.get<{
          type: string
          properties: any
          clientID: string
          redirectURI: string
          subject: string
          ttl: {
            access: number
            refresh: number
          }
          pkce?: AuthorizationState["pkce"]
          expiresAt: number
        }>(storage, key)
        if (!payload || !Number.isSafeInteger(payload.expiresAt) || payload.expiresAt <= Date.now()) {
          return c.json(
            {
              error: "invalid_grant",
              error_description: "Authorization code has been used or expired",
            },
            400,
          )
        }
        if (payload.redirectURI !== form.get("redirect_uri")) {
          return c.json(
            {
              error: "invalid_redirect_uri",
              error_description: "Redirect URI mismatch",
            },
            400,
          )
        }
        if (payload.clientID !== form.get("client_id")) {
          return c.json(
            {
              error: "unauthorized_client",
              error_description:
                "Client is not authorized to use this authorization code",
            },
            403,
          )
        }

        const codeVerifier = form.get("code_verifier")?.toString()
        if (
          !payload.pkce || !codeVerifier ||
          !(await validatePKCE(codeVerifier, payload.pkce.challenge, payload.pkce.method))
        ) {
          return c.json({ error: "invalid_grant", error_description: "Invalid PKCE proof" }, 400)
        }
        // TODO: replace get/remove with atomic consume on a transactional store.
        const tokens = await generateTokens(c, payload)
        await Storage.remove(storage, key)
        return c.json({
          access_token: tokens.access,
          token_type: "Bearer",
          expires_in: tokens.expiresIn,
          refresh_token: tokens.refresh,
        })
      }

      if (grantType === "refresh_token") {
        const refreshToken = form.get("refresh_token")
        if (!refreshToken)
          return c.json(
            {
              error: "invalid_request",
              error_description: "Missing refresh_token",
            },
            400,
          )
        const splits = refreshToken.toString().split(":")
        const token = splits.pop()!
        const subject = splits.join(":")
        const key = ["oauth:refresh", subject, token]
        const payload = await Storage.get<{
          type: string
          properties: any
          clientID: string
          subject: string
          ttl: {
            access: number
            refresh: number
          }
          nextToken: string
          timeUsed?: number
        }>(storage, key)
        if (!payload) {
          return c.json(
            {
              error: "invalid_grant",
              error_description: "Refresh token has been used or expired",
            },
            400,
          )
        }
        if (form.get("client_id") !== payload.clientID) {
          return c.json({ error: "invalid_grant", error_description: "Client mismatch" }, 400)
        }
        const generateRefreshToken = !payload.timeUsed
        if (ttlRefreshReuse <= 0) {
          // no reuse interval, remove the refresh token immediately
          await Storage.remove(storage, key)
        } else if (!payload.timeUsed) {
          payload.timeUsed = Date.now()
          await Storage.set(
            storage,
            key,
            payload,
            ttlRefreshReuse + ttlRefreshRetention,
          )
        } else if (Date.now() > payload.timeUsed + ttlRefreshReuse * 1000) {
          // token was reused past the allowed interval
          await auth.invalidate(subject)
          return c.json(
            {
              error: "invalid_grant",
              error_description: "Refresh token has been used or expired",
            },
            400,
          )
        }
        const tokens = await generateTokens(c, payload, {
          generateRefreshToken,
        })
        return c.json({
          access_token: tokens.access,
          token_type: "Bearer",
          refresh_token: tokens.refresh,
          expires_in: tokens.expiresIn,
        })
      }

      if (grantType === "client_credentials") {
        const provider = form.get("provider")
        if (!provider)
          return c.json({ error: "missing `provider` form value" }, 400)
        const match = Object.hasOwn(input.providers, provider.toString())
          ? input.providers[provider.toString()]
          : undefined
        if (!match)
          return c.json({ error: "invalid `provider` query parameter" }, 400)
        if (!match.client)
          return c.json(
            { error: "this provider does not support client_credentials" },
            400,
          )
        const clientID = form.get("client_id")
        const clientSecret = form.get("client_secret")
        if (!clientID)
          return c.json({ error: "missing `client_id` form value" }, 400)
        if (!clientSecret)
          return c.json({ error: "missing `client_secret` form value" }, 400)
        const response = await match.client({
          clientID: clientID.toString(),
          clientSecret: clientSecret.toString(),
          params: Object.fromEntries(form) as Record<string, string>,
        })
        return input.success(
          {
            async subject(type, properties, opts) {
              const tokens = await generateTokens(c, {
                type: type as string,
                subject:
                  opts?.subject || (await resolveSubject(type, properties)),
                properties,
                clientID: clientID.toString(),
                ttl: {
                  access: opts?.ttl?.access ?? ttlAccess,
                  refresh: opts?.ttl?.refresh ?? ttlRefresh,
                },
              })
              return c.json({
                access_token: tokens.access,
                token_type: "Bearer",
                refresh_token: tokens.refresh,
                expires_in: tokens.expiresIn,
              })
            },
          },
          {
            provider: provider.toString(),
            ...response,
          },
          c.req.raw,
        )
      }

      return c.json({ error: "unsupported_grant_type" }, 400)
    },
  )

  app.get("/authorize", async (c) => {
    const params = new URL(c.req.url).searchParams
    for (const name of ["provider", "response_type", "redirect_uri", "state", "client_id", "audience", "code_challenge", "code_challenge_method"]) {
      if (params.getAll(name).length > 1) {
        return c.json({ error: "invalid_request", error_description: `Duplicate ${name}` }, 400)
      }
    }
    const provider = params.get("provider")
    const redirect_uri = params.get("redirect_uri")
    const client_id = params.get("client_id")
    const challenge = params.get("code_challenge")
    const method = params.get("code_challenge_method")
    if (!client_id || !isSafeRedirectURI(redirect_uri)) {
      return c.json({ error: "invalid_request" }, 400)
    }
    if (params.get("response_type") !== "code") {
      return c.json({ error: "unsupported_response_type" }, 400)
    }
    if (!isPKCEChallenge(challenge, method)) {
      return c.json({ error: "invalid_request", error_description: "S256 PKCE is required" }, 400)
    }
    if (provider !== null && !Object.hasOwn(input.providers, provider)) {
      return c.json({ error: "invalid_request", error_description: "Unknown provider" }, 400)
    }
    const authorization: AuthorizationState = {
      response_type: "code",
      redirect_uri,
      client_id,
      state: params.get("state") ?? "",
      audience: params.get("audience") ?? undefined,
      pkce: { challenge, method: "S256" },
    }
    if (!(await allowAuthorization(authorization, c.req.raw))) {
      return c.json({ error: "unauthorized_client" }, 400)
    }
    // Only validated destinations are eligible for later error redirects.
    c.set("authorization", authorization)
    if (input.start) await input.start(c.req.raw)
    await auth.set(c, "authorization", 60 * 10, authorization)
    if (provider) return c.redirect(`/${provider}/authorize`)
    const providers = Object.keys(input.providers)
    if (providers.length === 1) return c.redirect(`/${providers[0]}/authorize`)
    return auth.forward(
      c,
      await select()(
        Object.fromEntries(
          Object.entries(input.providers).map(([key, value]) => [
            key,
            value.type,
          ]),
        ),
        c.req.raw,
      ),
    )
  })

  app.get("/userinfo", async (c) => {
    const header = c.req.header("Authorization")

    if (!header) {
      return c.json(
        {
          error: "invalid_request",
          error_description: "Missing Authorization header",
        },
        400,
      )
    }

    const [type, token] = header.split(" ")

    if (type !== "Bearer") {
      return c.json(
        {
          error: "invalid_request",
          error_description: "Missing or invalid Authorization header",
        },
        400,
      )
    }

    if (!token) {
      return c.json(
        {
          error: "invalid_request",
          error_description: "Missing token",
        },
        400,
      )
    }

    const result = await jwtVerify<{
      mode: "access"
      type: keyof SubjectSchema
      properties: v1.InferInput<SubjectSchema[keyof SubjectSchema]>
    }>(token, () => signingKey().then((item) => item.public), {
      issuer: issuer(c),
    })

    const validated = await input.subjects[result.payload.type][
      "~standard"
    ].validate(result.payload.properties)

    if (!validated.issues && result.payload.mode === "access") {
      return c.json(validated.value as SubjectSchema)
    }

    return c.json({
      error: "invalid_token",
      error_description: "Invalid token",
    })
  })

  app.onError(async (err, c) => {
    console.error(err)
    const oauth = err instanceof OauthError
      ? err
      : new OauthError("server_error", "Internal server error")
    const body = { error: oauth.error, error_description: oauth.description }
    // Token/API errors must never use browser cookies as a redirect destination.
    if (c.req.path === "/token") return c.json(body, err instanceof OauthError ? 400 : 500)
    if (c.req.path === "/userinfo") {
      c.header("WWW-Authenticate", 'Bearer error="invalid_token"')
      return c.json({ error: "invalid_token" }, 401)
    }
    if (c.req.path === "/authorize") return c.json(body, err instanceof OauthError ? 400 : 500)
    if (err instanceof UnknownStateError) {
      return auth.forward(c, await error(err, c.req.raw))
    }
    try {
      const authorization = await getAuthorization(c)
      const url = new URL(authorization.redirect_uri)
      url.searchParams.set("error", oauth.error)
      url.searchParams.set("error_description", oauth.description)
      url.searchParams.set("state", authorization.state)
      return c.redirect(url.toString())
    } catch {
      return c.json(body, 400)
    }
  })

  return app
}
