/**
 * Configures a provider that supports username and password authentication. This is usually
 * paired with the `PasswordUI`.
 *
 * ```ts
 * import { PasswordUI } from "@openauthjs/openauth/ui/password"
 * import { PasswordProvider } from "@openauthjs/openauth/provider/password"
 *
 * export default issuer({
 *   providers: {
 *     password: PasswordProvider(
 *       PasswordUI({
 *         copy: {
 *           error_email_taken: "This email is already taken."
 *         },
 *         sendCode: (email, code) => console.log(email, code)
 *       })
 *     )
 *   },
 *   // ...
 * })
 * ```
 *
 * Behind the scenes, the `PasswordProvider` expects callbacks that implements request handlers
 * that generate the UI for the following.
 *
 * ```ts
 * PasswordProvider({
 *   // ...
 *   login: (req, form, error) => Promise<Response>
 *   register: (req, state, form, error) => Promise<Response>
 *   change: (req, state, form, error) => Promise<Response>
 * })
 * ```
 *
 * This allows you to create your own UI for each of these screens.
 *
 * @packageDocumentation
 */
import { Storage, type StorageAdapter } from "../storage/storage.js"
import type { SecurityStorage } from "../storage/security.js"
import { Provider } from "./provider.js"
import { generateUnbiasedDigits, timingSafeCompare } from "../random.js"
import { v1 } from "@standard-schema/spec"
import type { Context } from "hono"
import { hashSecret, passwordReturnURL, randomSecret, validPasswordOrigin } from "../security-utils.js"

/**
 * @internal
 */
export interface PasswordHasher<T> {
  hash(password: string): Promise<T>
  verify(password: string, compare: T): Promise<boolean>
}

export interface PasswordConfig {
  /**
   * @internal
   */
  length?: number
  /**
   * @internal
   */
  hasher?: PasswordHasher<any>
  /**
   * The request handler to generate the UI for the login screen.
   *
   * Takes the standard [`Request`](https://developer.mozilla.org/en-US/docs/Web/API/Request)
   * and optionally [`FormData`](https://developer.mozilla.org/en-US/docs/Web/API/FormData)
   * ojects.
   *
   * In case of an error, this is called again with the `error`.
   *
   * Expects the [`Response`](https://developer.mozilla.org/en-US/docs/Web/API/Response) object
   * in return.
   */
  login: (
    req: Request,
    form?: FormData,
    error?: PasswordLoginError,
    /** 自定义表单必须将此值放入名为 csrf 的隐藏字段。 */
    csrfToken?: string,
  ) => Promise<Response>
  /**
   * The request handler to generate the UI for the register screen.
   *
   * Takes the standard [`Request`](https://developer.mozilla.org/en-US/docs/Web/API/Request)
   * and optionally [`FormData`](https://developer.mozilla.org/en-US/docs/Web/API/FormData)
   * ojects.
   *
   * Also passes in the current `state` of the flow and any `error` that occurred.
   *
   * Expects the [`Response`](https://developer.mozilla.org/en-US/docs/Web/API/Response) object
   * in return.
   */
  register: (
    req: Request,
    state: PasswordRegisterState,
    form?: FormData,
    error?: PasswordRegisterError,
    /** 自定义表单必须将此值放入名为 csrf 的隐藏字段。 */
    csrfToken?: string,
  ) => Promise<Response>
  /**
   * The request handler to generate the UI for the change password screen.
   *
   * Takes the standard [`Request`](https://developer.mozilla.org/en-US/docs/Web/API/Request)
   * and optionally [`FormData`](https://developer.mozilla.org/en-US/docs/Web/API/FormData)
   * ojects.
   *
   * Also passes in the current `state` of the flow and any `error` that occurred.
   *
   * Expects the [`Response`](https://developer.mozilla.org/en-US/docs/Web/API/Response) object
   * in return.
   */
  change: (
    req: Request,
    state: PasswordChangeState,
    form?: FormData,
    error?: PasswordChangeError,
    /** 自定义表单必须将此值放入名为 csrf 的隐藏字段。 */
    csrfToken?: string,
  ) => Promise<Response>
  /**
   * Callback to send the confirmation pin code to the user.
   *
   * @example
   * ```ts
   * {
   *   sendCode: async (email, code) => {
   *     // Send an email with the code
   *   }
   * }
   * ```
   */
  sendCode: (email: string, code: string) => Promise<void>
  /**
   * Callback to validate the password on sign up and password reset.
   *
   * @example
   * ```ts
   * {
   *   validatePassword: (password) => {
   *      return password.length < 8 ? "Password must be at least 8 characters" : undefined
   *   }
   * }
   * ```
   */
  validatePassword?:
    | v1.StandardSchema
    | ((password: string) => Promise<string | undefined> | string | undefined)
}

/**
 * The states that can happen on the register screen.
 *
 * | State | Description |
 * | ----- | ----------- |
 * | `start` | The user is asked to enter their email address and password to start the flow. |
 * | `code` | The user needs to enter the pin code to verify their email. |
 */
export type PasswordRegisterState =
  | {
      type: "start"
    }
  | {
      type: "code"
      /** @deprecated 保留字段兼容 UI 类型，值为空；验证码只在服务端处理。 */
      code: string
      email: string
      /** @deprecated 保留字段兼容 UI 类型，值为空；密码哈希不发送给 UI。 */
      password: string
    }

/**
 * The errors that can happen on the register screen.
 *
 * | Error | Description |
 * | ----- | ----------- |
 * | `email_taken` | The email is already taken. |
 * | `invalid_email` | The email is invalid. |
 * | `invalid_code` | The code is invalid. |
 * | `invalid_password` | The password is invalid. |
 * | `password_mismatch` | The passwords do not match. |
 */
export type PasswordRegisterError =
  | {
      type: "invalid_code"
    }
  | {
      type: "email_taken"
    }
  | {
      type: "invalid_email"
    }
  | {
      type: "invalid_password"
    }
  | {
      type: "password_mismatch"
    }
  | {
      type: "validation_error"
      message?: string
    }

/**
 * The state of the password change flow.
 *
 * | State | Description |
 * | ----- | ----------- |
 * | `start` | The user is asked to enter their email address to start the flow. |
 * | `code` | The user needs to enter the pin code to verify their email. |
 * | `update` | The user is asked to enter their new password and confirm it. |
 */
export type PasswordChangeState =
  | {
      type: "start"
      redirect: string
    }
  | {
      type: "code"
      /** @deprecated 保留字段兼容 UI 类型，值为空；验证码只在服务端处理。 */
      code: string
      email: string
      redirect: string
    }
  | {
      type: "update"
      redirect: string
      email: string
    }

/**
 * The errors that can happen on the change password screen.
 *
 * | Error | Description |
 * | ----- | ----------- |
 * | `invalid_email` | The email is invalid. |
 * | `invalid_code` | The code is invalid. |
 * | `invalid_password` | The password is invalid. |
 * | `password_mismatch` | The passwords do not match. |
 */
export type PasswordChangeError =
  | {
      type: "invalid_email"
    }
  | {
      type: "invalid_code"
    }
  | {
      type: "invalid_password"
    }
  | {
      type: "password_mismatch"
    }
  | {
      type: "validation_error"
      message: string
    }

/**
 * The errors that can happen on the login screen.
 *
 * | Error | Description |
 * | ----- | ----------- |
 * | `invalid_email` | The email is invalid. |
 * | `invalid_password` | The password is invalid. |
 */
export type PasswordLoginError =
  | {
      type: "invalid_password"
    }
  | {
      type: "invalid_email"
    }

interface PasswordHandle {
  kind: "login" | "register" | "reset"
  csrf: string
  flowID?: string
  redirect?: string
}

export function PasswordProvider(
  config: PasswordConfig,
): Provider<{ email: string }> {
  const hasher = config.hasher ?? ScryptHasher()
  const dummyHash = lazy(() => hasher.hash(randomSecret()))

  async function validate(password: string) {
    if (password.length > 1024) return "Password is too long"
    if (!config.validatePassword) {
      return password.length < 12 ? "Password must contain at least 12 characters" : undefined
    }
    try {
      if (typeof config.validatePassword === "function") return await config.validatePassword(password)
      const result = await config.validatePassword["~standard"].validate(password)
      return result.issues?.length ? "Password does not meet requirements" : undefined
    } catch {
      // 校验器异常必须拒绝密码，不能因非 Error 异常而默认为通过。
      return "Password validation failed"
    }
  }

  function emailOf(value: FormDataEntryValue | null) {
    if (typeof value !== "string") return
    const email = value.trim().toLowerCase()
    if (email.length > 254 || !/^[^\s@\u0000-\u001f\u007f]+@[^\s@\u0000-\u001f\u007f]+$/.test(email)) return
    return email
  }

  return {
    type: "password",
    init(routes, ctx) {
      const accountKey = (email: string) => JSON.stringify([ctx.name, email])
      const cookieKey = (kind: PasswordHandle["kind"]) => `password_${ctx.name}_${kind}`

      async function credentialFor(email: string) {
        // 迁移由受信任的管理操作显式执行；运行时不读取 KV，避免误切命名空间后旧密码复活。
        return ctx.security.execute("getCredential", { account: accountKey(email) })
      }

      async function start(c: Context, kind: PasswordHandle["kind"], redirect?: string) {
        const handle: PasswordHandle = { kind, csrf: randomSecret(), redirect }
        await ctx.set(c, cookieKey(kind), 600, handle)
        return handle
      }

      async function read(c: Context, kind: PasswordHandle["kind"], form: FormData) {
        const handle = await ctx.get<PasswordHandle | undefined>(c, cookieKey(kind))
        const csrf = form.get("csrf")
        if (!handle || handle.kind !== kind || typeof csrf !== "string" ||
            !/^[A-Za-z0-9_-]{43}$/.test(csrf) || !timingSafeCompare(csrf, handle.csrf) ||
            !validPasswordOrigin(c.req.raw, new URL(getRelativeUrl(c, "/")).origin)) {
          return undefined
        }
        for (const name of ["action", "email", "password", "repeat", "code", "csrf"]) {
          const values = form.getAll(name)
          if (values.length > 1 || values.some((value) => typeof value !== "string")) return undefined
        }
        return handle
      }

      async function view(handle: PasswordHandle) {
        if (!handle.flowID) return
        return ctx.security.execute("getFlow", {
          flowID: handle.flowID, csrfHash: await hashSecret(handle.csrf),
        })
      }

      routes.get("/authorize", async (c) => {
        const handle = await start(c, "login")
        return ctx.forward(c, await config.login(c.req.raw, undefined, undefined, handle.csrf))
      })

      routes.post("/authorize", async (c) => {
        const form = await c.req.formData()
        const handle = await read(c, "login", form)
        if (!handle) return c.text("Invalid login request", 400)
        const error = (err: PasswordLoginError) =>
          config.login(c.req.raw, form, err, handle.csrf).then((response) => ctx.forward(c, response))
        const email = emailOf(form.get("email"))
        const password = form.get("password")?.toString()
        if (!email) return error({ type: "invalid_email" })
        if (!password || password.length > 1024) return error({ type: "invalid_password" })
        const account = accountKey(email)
        if (!(await ctx.security.execute("loginAttempt", { account }))) {
          c.header("Retry-After", "900")
          return c.text("Too many login attempts", 429)
        }
        const credential = await credentialFor(email)
        const valid = await hasher.verify(password, credential?.hash ?? await dummyHash())
        if (!valid || !credential ||
            !(await ctx.security.execute("finishLogin", { account, version: credential.version }))) {
          return error({ type: "invalid_password" })
        }
        await ctx.unset(c, cookieKey("login"))
        return ctx.success(c, { email }, {
          credential: { account, version: credential.version },
        })
      })

      routes.get("/register", async (c) => {
        const handle = await start(c, "register")
        return ctx.forward(c, await config.register(c.req.raw, { type: "start" }, undefined, undefined, handle.csrf))
      })

      routes.post("/register", async (c) => {
        const form = await c.req.formData()
        const handle = await read(c, "register", form)
        if (!handle) return c.text("Invalid registration request", 400)
        const flow = await view(handle)
        const state: PasswordRegisterState = flow
          ? { type: "code", email: flow.email, code: "", password: "" }
          : { type: "start" }
        const render = (next: PasswordRegisterState, error?: PasswordRegisterError) =>
          config.register(c.req.raw, next, form, error, handle.csrf).then((response) => ctx.forward(c, response))
        const action = form.get("action")
        if (action === "register") {
          const email = flow?.email ?? emailOf(form.get("email"))
          if (!email) return render(state, { type: "invalid_email" })
          let passwordHash: unknown
          if (!flow) {
            const password = form.get("password")?.toString()
            if (!password) return render(state, { type: "invalid_password" })
            if (password !== form.get("repeat")) return render(state, { type: "password_mismatch" })
            const message = await validate(password)
            if (message) return render(state, { type: "validation_error", message })
            if (!(await ctx.security.execute("loginAttempt", { account: "register:" + accountKey(email) }))) {
              return c.text("Too many registration attempts", 429)
            }
            passwordHash = await hasher.hash(password)
          }
          const code = generateUnbiasedDigits(6)
          const flowID = crypto.randomUUID()
          const status = await ctx.security.execute("beginFlow", {
            flowID, kind: "register", account: accountKey(email), email,
            csrfHash: await hashSecret(handle.csrf),
            codeHash: await hashSecret(JSON.stringify([flowID, code])),
            passwordHash, previousFlowID: handle.flowID,
          })
          if (status === "limited") {
            c.header("Retry-After", "3600")
            return c.text("Too many verification messages", 429)
          }
          if (status !== "ok") return render({ type: "start" }, { type: "email_taken" })
          handle.flowID = flowID
          await ctx.set(c, cookieKey("register"), 600, handle)
          // 事务已经提交后才发送邮件；邮件失败不会回滚次数或恢复旧验证码。
          await config.sendCode(email, code)
          return render({ type: "code", email, code: "", password: "" })
        }
        if (action === "verify" && handle.flowID && flow?.kind === "register") {
          const result = await ctx.security.execute("verifyFlow", {
            flowID: handle.flowID, csrfHash: await hashSecret(handle.csrf),
            codeHash: await hashSecret(JSON.stringify([handle.flowID, form.get("code")?.toString() ?? ""])),
          })
          if (!result.ok) {
            return render(state, { type: result.reason === "exists" ? "email_taken" : "invalid_code" })
          }
          if (result.kind !== "register" || !result.credential) return render(state, { type: "invalid_code" })
          await ctx.unset(c, cookieKey("register"))
          return ctx.success(c, { email: result.email }, { credential: result.credential })
        }
        return c.text("Invalid registration state", 400)
      })

      routes.get("/change", async (c) => {
        const redirect = passwordReturnURL(c.req.query("redirect_uri"), getRelativeUrl(c, "./authorize"))
        if (!redirect) return c.text("Invalid return URL", 400)
        const handle = await start(c, "reset", redirect)
        return ctx.forward(c, await config.change(c.req.raw, { type: "start", redirect }, undefined, undefined, handle.csrf))
      })

      routes.post("/change", async (c) => {
        const form = await c.req.formData()
        const handle = await read(c, "reset", form)
        if (!handle) return c.text("Invalid password reset request", 400)
        const redirect = passwordReturnURL(handle.redirect, getRelativeUrl(c, "./authorize"))
        if (!redirect) return c.text("Invalid return URL", 400)
        const flow = await view(handle)
        const state: PasswordChangeState = !flow ? { type: "start", redirect } :
          flow.phase === "code"
            ? { type: "code", email: flow.email, code: "", redirect }
            : { type: "update", email: flow.email, redirect }
        const render = (next: PasswordChangeState, error?: PasswordChangeError) =>
          config.change(c.req.raw, next, form, error, handle.csrf).then((response) => ctx.forward(c, response))
        const action = form.get("action")
        if (action === "code") {
          const email = emailOf(form.get("email"))
          if (!email) return render(state, { type: "invalid_email" })
          const code = generateUnbiasedDigits(6)
          const flowID = crypto.randomUUID()
          const status = await ctx.security.execute("beginFlow", {
            flowID, kind: "reset", account: accountKey(email), email,
            csrfHash: await hashSecret(handle.csrf),
            codeHash: await hashSecret(JSON.stringify([flowID, code])),
          })
          if (status !== "ok") {
            c.header("Retry-After", "3600")
            return c.text("Too many verification messages", 429)
          }
          handle.flowID = flowID
          await ctx.set(c, cookieKey("reset"), 600, handle)
          await config.sendCode(email, code)
          return render({ type: "code", email, code: "", redirect })
        }
        if (!flow || flow.kind !== "reset" || !handle.flowID) return c.text("Reset transaction expired", 400)
        if (action === "verify") {
          const result = await ctx.security.execute("verifyFlow", {
            flowID: handle.flowID, csrfHash: await hashSecret(handle.csrf),
            codeHash: await hashSecret(JSON.stringify([handle.flowID, form.get("code")?.toString() ?? ""])),
          })
          if (!result.ok || result.kind !== "reset") return render(state, { type: "invalid_code" })
          return render({ type: "update", email: result.email, redirect })
        }
        if (action === "update" && flow.phase === "update") {
          const password = form.get("password")?.toString()
          if (!password) return render(state, { type: "invalid_password" })
          if (password !== form.get("repeat")) return render(state, { type: "password_mismatch" })
          const message = await validate(password)
          if (message) return render(state, { type: "validation_error", message })
          const completed = await ctx.security.execute("completeReset", {
            flowID: handle.flowID, csrfHash: await hashSecret(handle.csrf),
            passwordHash: await hasher.hash(password),
          })
          if (!completed) return c.text("Reset transaction is no longer valid", 400)
          await ctx.unset(c, cookieKey("reset"))
          return c.redirect(redirect, 302)
        }
        return c.text("Invalid reset state", 400)
      })
    },
  }
}

import * as jose from "jose"
import { TextEncoder } from "node:util"

interface HashedPassword {}

/**
 * @internal
 */
export function PBKDF2Hasher(opts?: { iterations?: number }): PasswordHasher<{
  hash: string
  salt: string
  iterations: number
}> {
  const iterations = opts?.iterations ?? 600000
  return {
    async hash(password) {
      const encoder = new TextEncoder()
      const bytes = encoder.encode(password)
      const salt = crypto.getRandomValues(new Uint8Array(16))
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        bytes,
        "PBKDF2",
        false,
        ["deriveBits"],
      )
      const hash = await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          hash: "SHA-256",
          salt: salt,
          iterations,
        },
        keyMaterial,
        256,
      )
      const hashBase64 = jose.base64url.encode(new Uint8Array(hash))
      const saltBase64 = jose.base64url.encode(salt)
      return {
        hash: hashBase64,
        salt: saltBase64,
        iterations,
      }
    },
    async verify(password, compare) {
      const encoder = new TextEncoder()
      const passwordBytes = encoder.encode(password)
      const salt = jose.base64url.decode(compare.salt)
      const params = {
        name: "PBKDF2",
        hash: "SHA-256",
        salt,
        iterations: compare.iterations,
      }
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        passwordBytes,
        "PBKDF2",
        false,
        ["deriveBits"],
      )
      const hash = await crypto.subtle.deriveBits(params, keyMaterial, 256)
      const hashBase64 = jose.base64url.encode(new Uint8Array(hash))
      return timingSafeCompare(hashBase64, compare.hash)
    },
  }
}
import { timingSafeEqual, randomBytes, scrypt } from "node:crypto"
import { getRelativeUrl, lazy } from "../util.js"

/**
 * @internal
 */
export function ScryptHasher(opts?: {
  N?: number
  r?: number
  p?: number
}): PasswordHasher<{
  hash: string
  salt: string
  N: number
  r: number
  p: number
}> {
  const N = opts?.N ?? 16384
  const r = opts?.r ?? 8
  const p = opts?.p ?? 1

  return {
    async hash(password) {
      const salt = randomBytes(16)
      const keyLength = 32 // 256 bits

      const derivedKey = await new Promise<Buffer>((resolve, reject) => {
        scrypt(password, salt, keyLength, { N, r, p }, (err, derivedKey) => {
          if (err) reject(err)
          else resolve(derivedKey)
        })
      })

      const hashBase64 = derivedKey.toString("base64")
      const saltBase64 = salt.toString("base64")

      return {
        hash: hashBase64,
        salt: saltBase64,
        N,
        r,
        p,
      }
    },

    async verify(password, compare) {
      const salt = Buffer.from(compare.salt, "base64")
      const keyLength = 32 // 256 bits

      const derivedKey = await new Promise<Buffer>((resolve, reject) => {
        scrypt(
          password,
          salt,
          keyLength,
          { N: compare.N, r: compare.r, p: compare.p },
          (err, derivedKey) => {
            if (err) reject(err)
            else resolve(derivedKey)
          },
        )
      })

      return timingSafeEqual(derivedKey, Buffer.from(compare.hash, "base64"))
    },
  }
}

/**
 * 切换流量前，在受信任的 Worker 管理环境执行一次。
 * 不覆盖已存在或已经改密的账号；不得把此迁移函数暴露为公共注册接口。
 */
export async function migratePasswordCredentials(
  storage: StorageAdapter,
  security: SecurityStorage,
  providerName = "password",
) {
  if (!/^[A-Za-z0-9_-]+$/.test(providerName)) throw new Error("Invalid provider name")
  let imported = 0
  let skipped = 0
  for await (const [parts, hash] of Storage.scan<HashedPassword>(storage, ["email"])) {
    if (parts.length !== 3 || parts[0] !== "email" || parts[2] !== "password") continue
    const email = parts[1]
    if (email !== email.trim().toLowerCase() ||
        /[\u0000-\u001f\u007f]/.test(email)) {
      throw new Error("Legacy email requires manual normalization")
    }
    const account = JSON.stringify([providerName, email])
    if (await security.execute("getCredential", { account })) { skipped++; continue }
    await security.execute("importCredential", { account, hash })
    imported++
  }
  return { imported, skipped }
}
