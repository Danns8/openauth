import assert from "node:assert/strict"
import { test } from "bun:test"
import {
  basicCredentials, clientAuthenticator, expiringCache, hashSecret,
  newRefreshToken, parseRefreshToken, passwordReturnURL, validPasswordOrigin,
} from "../src/security-utils.js"
import { CloudflareStorage } from "../src/storage/cloudflare.js"
import { Storage, joinKey } from "../src/storage/storage.js"

const secret = "test-only-client-secret-with-at-least-32-characters"
const clients = {
  web: { redirectURIs: ["https://web.test/callback"], clientSecret: secret },
  spa: { redirectURIs: ["https://spa.test/callback"] },
}
function form(values: Record<string, string>) {
  const result = new FormData()
  for (const [key, value] of Object.entries(values)) result.set(key, value)
  return result
}
const request = (authorization?: string) => new Request("https://auth.test/token", {
  method: "POST", headers: authorization ? { Authorization: authorization } : {},
})

test("机密客户端必须认证，不能只携带客户端 ID", async () => {
  const authenticate = clientAuthenticator(clients)
  assert.equal(await authenticate(request(), form({ client_id: "web" })), undefined)
  assert.equal(await authenticate(request(), form({ client_id: "web", client_secret: "wrong" })), undefined)
  assert.equal(await authenticate(request(basicCredentials("web", secret)), form({ client_id: "web" })), "web")
  assert.equal(await authenticate(request(), form({ client_id: "web", client_secret: secret })), "web")
})

test("公共客户端和未知客户端不能混用认证类型", async () => {
  const authenticate = clientAuthenticator(clients)
  assert.equal(await authenticate(request(), form({ client_id: "spa" })), "spa")
  assert.equal(await authenticate(request(), form({ client_id: "missing" })), undefined)
  assert.equal(await authenticate(request(), form({ client_id: "spa", client_secret: secret })), undefined)
})

test("Basic 与表单身份必须一致且不能同时提供两种凭据", async () => {
  const authenticate = clientAuthenticator(clients)
  const header = basicCredentials("web", secret)
  assert.equal(await authenticate(request(header), form({ client_id: "spa" })), undefined)
  assert.equal(await authenticate(request(header), form({ client_id: "web", client_secret: secret })), undefined)
  assert.equal(await authenticate(request(header), form({})), "web")
})

test("Basic 保留协议要求的编码，畸形凭据必须拒绝", async () => {
  const clientID = "web:中文+%"
  const authenticate = clientAuthenticator({ [clientID]: { redirectURIs: [], clientSecret: secret } })
  assert.equal(await authenticate(request(basicCredentials(clientID, secret)), form({})), clientID)
  for (const header of ["Bearer x", "Basic !!!", "Basic " + btoa("web"), "Basic " + btoa("web:%XX")]) {
    assert.equal(await authenticate(request(header), form({})), undefined)
  }
  assert.throws(() => clientAuthenticator({ web: { redirectURIs: [], clientSecret: "short" } }))
})

test("刷新格式拒绝旧会话并生成不可预测的新凭据", async () => {
  const first = newRefreshToken()
  const parsed = parseRefreshToken(first)!
  assert.ok(parsed)
  assert.notEqual(newRefreshToken(parsed.familyID), first)
  assert.equal(parseRefreshToken(newRefreshToken(parsed.familyID))!.familyID, parsed.familyID)
  for (const value of ["user:123:old-uuid", "", first + ".", first.replace("v2.", "v1."), null]) {
    assert.equal(parseRefreshToken(value), undefined)
  }
  assert.equal((await hashSecret(first)).length, 43)
})

test("改密返回地址只能留在认证站点", () => {
  const fallback = "https://auth.test/password/authorize"
  assert.equal(passwordReturnURL(undefined, fallback), fallback)
  assert.equal(passwordReturnURL("./authorize", fallback), fallback)
  for (const value of ["https://evil.test", "//evil.test", "javascript:alert(1)", "/x#fragment", "/x\\\\evil", "https://user@auth.test/"]) {
    assert.equal(passwordReturnURL(value, fallback), undefined)
  }
})

test("表单拒绝跨站来源和 null 来源，无来源仍要求外层 CSRF 校验", () => {
  const check = (headers: Record<string, string>) =>
    validPasswordOrigin(new Request("https://auth.test/password/change", { headers }), "https://auth.test")
  assert.equal(check({ Origin: "https://auth.test" }), true)
  assert.equal(check({ Origin: "https://evil.test" }), false)
  assert.equal(check({ Origin: "null" }), false)
  assert.equal(check({ "Sec-Fetch-Site": "cross-site" }), false)
  assert.equal(check({}), true)
})

test("缓存合并并发请求且在截止后重新加载", async () => {
  let now = 1000
  const original = Date.now
  Date.now = () => now
  try {
    let calls = 0
    const load = expiringCache(async () => ++calls)
    const values = await Promise.all(Array.from({ length: 10 }, () => load()))
    assert.deepEqual(values, Array(10).fill(1))
    assert.equal(await load(true), 1)
    now += 5000
    assert.equal(await load(true), 2)
    now += 30000
    assert.equal(await load(), 3)
  } finally { Date.now = original }
})

test("缓存加载失败不无限使用过期结果，也不反复请求", async () => {
  let now = 1000
  const original = Date.now
  Date.now = () => now
  try {
    let calls = 0
    const load = expiringCache(async () => {
      calls++
      if (calls > 1) throw new Error("test unavailable")
      return "first"
    })
    assert.equal(await load(), "first")
    now += 30000
    await assert.rejects(load())
    await assert.rejects(load())
    assert.equal(calls, 2)
    now += 5000
    await assert.rejects(load())
    assert.equal(calls, 3)
  } finally { Date.now = original }
})

function kvFixture() {
  const rows = new Map<string, unknown>()
  const writes: any[] = []
  const namespace = {
    get: async (key: string) => rows.get(key) ?? null,
    put: async (key: string, value: string, options: unknown) => {
      writes.push(options)
      rows.set(key, JSON.parse(value))
    },
    delete: async (key: string) => { rows.delete(key) },
    list: async ({ prefix }: { prefix: string }) => ({
      keys: [...rows.keys()].filter((name) => name.startsWith(prefix)).map((name) => ({ name })),
      list_complete: true,
    }),
  }
  return {
    rows, writes,
    store: CloudflareStorage({ namespace: namespace as any }),
  }
}

test("KV 短期记录在逻辑截止时间失效，不等物理清理", async () => {
  const f = kvFixture()
  const original = Date.now
  let now = 1_700_000_000_000
  Date.now = () => now
  try {
    await Storage.set(f.store, ["sample", "short"], { ok: true }, 5)
    assert.equal(f.writes[0].expirationTtl, 60)
    assert.deepEqual(await Storage.get(f.store, ["sample", "short"]), { ok: true })
    now += 5000
    assert.equal(await Storage.get(f.store, ["sample", "short"]), undefined)
    const scanned = []
    for await (const entry of Storage.scan(f.store, ["sample"])) scanned.push(entry)
    assert.deepEqual(scanned, [])
    assert.equal(f.rows.size, 1)
  } finally { Date.now = original }
})

test("零 TTL 删除，未设置 TTL 保留，非法 TTL 拒绝", async () => {
  const f = kvFixture()
  await Storage.set(f.store, ["sample", "one"], { ok: true })
  assert.deepEqual(await Storage.get(f.store, ["sample", "one"]), { ok: true })
  assert.equal(f.writes[0].expirationTtl, undefined)
  await Storage.set(f.store, ["sample", "one"], { ok: true }, 0)
  assert.equal(await Storage.get(f.store, ["sample", "one"]), undefined)
  for (const ttl of [-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER]) {
    await assert.rejects(async () => Storage.set(f.store, ["sample", "one"], {}, ttl))
  }
})

test("普通旧 KV 数据兼容，但带版本的新数据必须通过截止校验", async () => {
  const f = kvFixture()
  const key = ["email", "test@example.test", "password"]
  f.rows.set(joinKey(key), { hash: "legacy-hash", salt: "legacy-salt" })
  assert.deepEqual(await Storage.get(f.store, key), { hash: "legacy-hash", salt: "legacy-salt" })
  f.rows.set(joinKey(key), { __openauth_storage: 2, value: "not-valid", expiresAt: "tomorrow" })
  assert.equal(await Storage.get(f.store, key), undefined)
})
