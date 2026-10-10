import assert from "node:assert/strict"
import { test } from "bun:test"
import { object, string } from "valibot"
import { issuer } from "../src/issuer.js"
import { createClient } from "../src/client.js"
import { createSubjects } from "../src/subject.js"
import { PasswordProvider, migratePasswordCredentials } from "../src/provider/password.js"
import { MemoryStorage } from "../src/storage/memory.js"
import { MemorySecurityStorage } from "../src/storage/security.js"
import { Storage } from "../src/storage/storage.js"

const ORIGIN = "https://auth.password.test"
const CALLBACK = "https://web.password.test/callback"
const EMAIL = "member@example.test"
const OLD = "original-password-123"
const NEW = "replacement-password-456"
const subjects = createSubjects({ user: object({ userID: string() }) })

class Cookies {
  values = new Map<string, string>()
  accept(response: Response) {
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";", 1)[0]
      const at = pair.indexOf("=")
      const name = pair.slice(0, at)
      if (/max-age=0(?:;|$)/i.test(cookie)) this.values.delete(name)
      else this.values.set(name, pair.slice(at + 1))
    }
  }
  header() { return [...this.values].map(([name, value]) => `${name}=${value}`).join("; ") }
  clone() { const result = new Cookies(); result.values = new Map(this.values); return result }
}

function fixture() {
  let now = Date.now()
  const security = MemorySecurityStorage(() => now)
  const storage = MemoryStorage()
  const sent: { email: string; code: string }[] = []
  const app = issuer({
    issuer: ORIGIN, storage, security, subjects,
    clients: { web: { redirectURIs: [CALLBACK] } },
    providers: {
      password: PasswordProvider({
        // 测试只关注状态流转；这个可逆假哈希绝不能用于真实部署。
        hasher: {
          hash: async (value) => ({ testPassword: value }),
          verify: async (value, hash) => hash.testPassword === value,
        },
        sendCode: async (email, code) => { sent.push({ email, code }) },
        login: async (_req, _form, error, csrf) =>
          Response.json({ error, csrf }, { status: error ? 401 : 200 }),
        register: async (_req, state, _form, error, csrf) =>
          Response.json({ state, error, csrf }, { status: error ? 400 : 200 }),
        change: async (_req, state, _form, error, csrf) =>
          Response.json({ state, error, csrf }, { status: error ? 400 : 200 }),
      }),
    },
    success: (ctx) => ctx.subject("user", { userID: "123" }, { subject: "custom:user:123" }),
  })
  const client = createClient({
    issuer: ORIGIN, clientID: "web",
    fetch: (url, init) => Promise.resolve(app.request(url, init)),
  })
  const request = async (path: string, jar: Cookies, init: RequestInit = {}) => {
    const headers = new Headers(init.headers)
    headers.set("cookie", jar.header())
    const response = await app.request(new URL(path, ORIGIN).toString(), { ...init, headers })
    jar.accept(response)
    return response
  }
  const post = (path: string, jar: Cookies, fields: Record<string, string>, origin = ORIGIN) =>
    request(path, jar, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: origin },
      body: new URLSearchParams(fields),
    })
  const reset = async () => {
    const jar = new Cookies()
    const start = await request("/password/change", jar)
    const { csrf } = await start.json()
    const send = await post("/password/change", jar, { action: "code", email: EMAIL, csrf })
    assert.equal(send.status, 200)
    return { jar, csrf, code: sent.at(-1)!.code }
  }
  const importOld = () => security.execute("importCredential", {
    account: JSON.stringify(["password", EMAIL]), hash: { testPassword: OLD },
  })
  const credential = () => security.execute("getCredential", { account: JSON.stringify(["password", EMAIL]) })
  return { app, client, security, storage, sent, request, post, reset, importOld, credential,
    advance: (ms: number) => { now += ms } }
}

test("真实 Password 路由改密后不能重复使用保存的 Cookie", async () => {
  const f = fixture()
  await f.importOld()
  const reset = await f.reset()
  assert.equal((await f.post("/password/change", reset.jar, {
    action: "verify", csrf: reset.csrf, code: reset.code,
  })).status, 200)
  const saved = reset.jar.clone()
  const changed = await f.post("/password/change", reset.jar, {
    action: "update", csrf: reset.csrf, password: NEW, repeat: NEW,
  })
  assert.equal(changed.status, 302)
  assert.ok(changed.headers.getSetCookie().some((value) =>
    value.startsWith("__Host-password_password_reset=") && /Secure/i.test(value) && /Max-Age=0/i.test(value)))
  assert.equal((await f.post("/password/change", saved, {
    action: "update", csrf: reset.csrf, password: OLD, repeat: OLD,
  })).status, 400)
  assert.deepEqual((await f.credential())!.hash, { testPassword: NEW })
})

test("原始 Cookie 重放不能重置验证码失败预算", async () => {
  const f = fixture()
  await f.importOld()
  const reset = await f.reset()
  const saved = reset.jar.clone()
  for (let i = 0; i < 5; i++) {
    assert.equal((await f.post("/password/change", saved.clone(), {
      action: "verify", csrf: reset.csrf, code: "invalid",
    })).status, 400)
  }
  assert.equal((await f.post("/password/change", saved, {
    action: "verify", csrf: reset.csrf, code: reset.code,
  })).status, 400)
})

test("服务端重置期限不受 Cookie 是否仍被发送影响", async () => {
  const f = fixture()
  await f.importOld()
  const reset = await f.reset()
  f.advance(600_000)
  assert.equal((await f.post("/password/change", reset.jar, {
    action: "verify", csrf: reset.csrf, code: reset.code,
  })).status, 400)
})

test("Password 表单需要正确 CSRF 和来源，返回地址不能离开认证站点", async () => {
  const f = fixture()
  const reset = await f.reset()
  const before = f.sent.length
  assert.equal((await f.post("/password/change", reset.jar, { action: "code", email: EMAIL })).status, 400)
  assert.equal((await f.post("/password/change", reset.jar, {
    action: "code", email: EMAIL, csrf: reset.csrf,
  }, "https://evil.test")).status, 400)
  assert.equal(f.sent.length, before)
  const other = await f.request("/password/register", reset.jar)
  const { csrf } = await other.json()
  assert.equal((await f.post("/password/change", reset.jar, {
    action: "code", email: EMAIL, csrf,
  })).status, 400)
  assert.equal((await f.request("/password/change?redirect_uri=https://evil.test", new Cookies())).status, 400)
})

test("重新发送使旧验证码失效，且服务端限制重复发送", async () => {
  const f = fixture()
  const reset = await f.reset()
  const oldCookie = reset.jar.clone()
  assert.equal((await f.post("/password/change", reset.jar, {
    action: "code", email: EMAIL, csrf: reset.csrf,
  })).status, 429)
  f.advance(60_000)
  assert.equal((await f.post("/password/change", reset.jar, {
    action: "code", email: EMAIL, csrf: reset.csrf,
  })).status, 200)
  // 偶然生成相同的六位数字不应使测试随机失败，因此此处用旧事务 Cookie 验证。
  const newCode = f.sent.at(-1)!.code
  assert.equal((await f.post("/password/change", oldCookie, {
    action: "verify", csrf: reset.csrf, code: reset.code,
  })).status, 400)
  assert.equal((await f.post("/password/change", reset.jar, {
    action: "verify", csrf: reset.csrf, code: newCode,
  })).status, 200)
})

test("注册后立即改密能撤销自定义 subject 的刷新会话", async () => {
  const f = fixture()
  const jar = new Cookies()
  const auth = await f.client.authorize(CALLBACK, "code", { provider: "password" })
  assert.equal((await f.request(auth.url, jar)).status, 302)
  const register = await f.request("/password/register", jar)
  const { csrf } = await register.json()
  const sent = await f.post("/password/register", jar, {
    action: "register", email: EMAIL, password: OLD, repeat: OLD, csrf,
  })
  assert.equal(sent.status, 200)
  const view = await sent.json()
  assert.equal(view.state.code, "")
  assert.equal(view.state.password, "")
  const registered = await f.post("/password/register", jar, {
    action: "verify", code: f.sent.at(-1)!.code, csrf,
  })
  assert.equal(registered.status, 302)
  const code = new URL(registered.headers.get("location")!).searchParams.get("code")!
  const result = await f.client.exchange(code, CALLBACK, auth.challenge.verifier)
  if (result.err) throw result.err
  assert.deepEqual((await f.credential())!.subjects, ["custom:user:123"])
  f.advance(60_000)
  const reset = await f.reset()
  await f.post("/password/change", reset.jar, { action: "verify", code: reset.code, csrf: reset.csrf })
  assert.equal((await f.post("/password/change", reset.jar, {
    action: "update", csrf: reset.csrf, password: NEW, repeat: NEW,
  })).status, 302)
  assert.ok((await f.client.refresh(result.tokens.refresh)).err)
})

test("并发 HTTP 授权码兑换只能成功一次", async () => {
  const f = fixture()
  await f.importOld()
  const jar = new Cookies()
  const auth = await f.client.authorize(CALLBACK, "code", { provider: "password" })
  await f.request(auth.url, jar)
  const login = await f.request("/password/authorize", jar)
  const { csrf } = await login.json()
  const response = await f.post("/password/authorize", jar, { email: EMAIL, password: OLD, csrf })
  assert.equal(response.status, 302)
  const code = new URL(response.headers.get("location")!).searchParams.get("code")!
  const results = await Promise.all(Array.from({ length: 10 }, () =>
    f.client.exchange(code, CALLBACK, auth.challenge.verifier)))
  assert.equal(results.filter((value) => !value.err).length, 1)
})

test("旧 KV 密码必须显式迁移，重复迁移不覆盖新密码", async () => {
  const f = fixture()
  await Storage.set(f.storage, ["email", EMAIL, "password"], { testPassword: OLD })
  assert.equal(await f.credential(), undefined)
  assert.deepEqual(await migratePasswordCredentials(f.storage, f.security), { imported: 1, skipped: 0 })
  const reset = await f.reset()
  await f.post("/password/change", reset.jar, { action: "verify", code: reset.code, csrf: reset.csrf })
  await f.post("/password/change", reset.jar, { action: "update", csrf: reset.csrf, password: NEW, repeat: NEW })
  assert.deepEqual(await migratePasswordCredentials(f.storage, f.security), { imported: 0, skipped: 1 })
  assert.deepEqual((await f.credential())!.hash, { testPassword: NEW })
})

test("旧刷新令牌不因 KV 中存在记录而恢复", async () => {
  const f = fixture()
  await Storage.set(f.storage, ["oauth:refresh", "old-user", "old-token"], {
    subject: "old-user", clientID: "web",
  })
  assert.ok((await f.client.refresh("old-user:old-token")).err)
})
