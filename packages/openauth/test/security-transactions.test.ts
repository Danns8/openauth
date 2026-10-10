import assert from "node:assert/strict"
import { test } from "bun:test"
import { MemorySecurityStorage, type Grant, type SecurityKey } from "../src/storage/security.js"

function fixture() {
  let now = 1_700_000_000_000
  const store = MemorySecurityStorage(() => now)
  const grant: Grant = {
    type: "user", properties: { userID: "123" }, subject: "user:123",
    clientID: "web", ttl: { access: 60, refresh: 600 },
  }
  const issue = (codeHash = "code", credential?: { account: string; version: number }) =>
    store.execute("issueCode", {
      codeHash, grant, redirectURI: "https://web.example.test/callback",
      challenge: "challenge", credential,
    })
  const redeem = (codeHash = "code", familyID = "family", overrides = {}) =>
    store.execute("redeemCode", {
      codeHash, familyID, refreshHash: "r0", clientID: "web",
      redirectURI: "https://web.example.test/callback", challenge: "challenge", ...overrides,
    })
  const rotate = (tokenHash = "r0", successorHash = "r1", extra = {}) =>
    store.execute("rotate", {
      familyID: "family", tokenHash, clientID: "web", successorHash,
      successorCiphertext: "sealed-" + successorHash, reuse: 60, ...extra,
    })
  const begin = (kind: "register" | "reset" = "reset", flowID = "flow", extra = {}) =>
    store.execute("beginFlow", {
      kind, flowID, account: "account", email: "test@example.test",
      csrfHash: "csrf", codeHash: "code-proof", ...extra,
    })
  const verify = (codeHash = "code-proof", flowID = "flow") =>
    store.execute("verifyFlow", { flowID, csrfHash: "csrf", codeHash })
  const complete = (flowID = "flow", passwordHash: unknown = "new-hash") =>
    store.execute("completeReset", { flowID, csrfHash: "csrf", passwordHash })
  const credential = () => store.execute("importCredential", { account: "account", hash: "old-hash" })
  return {
    store, grant, issue, redeem, rotate, begin, verify, complete, credential,
    advance: (milliseconds: number) => { now += milliseconds },
  }
}

test("同一授权码并发兑换最多成功一次", async () => {
  const f = fixture()
  await f.issue()
  const results = await Promise.all(Array.from({ length: 10 }, (_, i) => f.redeem("code", `family-${i}`)))
  assert.equal(results.filter(Boolean).length, 1)
})

test("错误 verifier、客户端或回调不消费授权码", async () => {
  const f = fixture()
  await f.issue()
  for (const overrides of [
    { challenge: "wrong" }, { clientID: "other" }, { redirectURI: "https://other.test" },
  ]) assert.equal(await f.redeem("code", "family", overrides), undefined)
  assert.ok(await f.redeem())
  assert.equal(await f.redeem(), undefined)
})

test("授权码到达截止时间即失效", async () => {
  const f = fixture()
  await f.issue()
  f.advance(60_000)
  assert.equal(await f.redeem(), undefined)
})

test("撤销后未兑换的旧授权码不能建立新会话", async () => {
  const f = fixture()
  await f.issue()
  await f.store.execute("revokeSubject", { subject: f.grant.subject })
  assert.equal(await f.redeem(), undefined)
  await f.issue("fresh")
  assert.ok(await f.redeem("fresh"))
})

test("刷新并发宽限只返回同一个后继", async () => {
  const f = fixture()
  await f.issue()
  await f.redeem()
  const results = await Promise.all(Array.from({ length: 10 }, (_, i) => f.rotate("r0", `next-${i}`)))
  assert.equal(results.filter(Boolean).length, 10)
  assert.equal(new Set(results.map((value) => value!.tokenCiphertext)).size, 1)
  assert.equal(new Set(results.map((value) => value!.timeUsed)).size, 1)
})

test("宽限外重放旧刷新令牌撤销整个族", async () => {
  const f = fixture()
  await f.issue()
  await f.redeem()
  assert.ok(await f.rotate())
  f.advance(60_001)
  assert.equal(await f.rotate("r0", "r2"), undefined)
  assert.equal(await f.rotate("r1", "r3"), undefined)
})

test("保留更早的刷新记录，不能通过多次轮换逃避重放检测", async () => {
  const f = fixture()
  await f.issue()
  await f.redeem()
  await f.rotate("r0", "r1")
  f.advance(1000)
  await f.rotate("r1", "r2")
  f.advance(60_000)
  assert.equal(await f.rotate("r0", "r3"), undefined)
  assert.equal(await f.rotate("r2", "r4"), undefined)
})

test("随机令牌或错误客户端不能撤销别人的刷新族", async () => {
  const f = fixture()
  await f.issue()
  await f.redeem()
  assert.equal(await f.rotate("random"), undefined)
  assert.equal(await f.rotate("r0", "r1", { clientID: "other" }), undefined)
  assert.ok(await f.rotate())
})

test("宽限内过时响应不返回已经使用的后继", async () => {
  const f = fixture()
  await f.issue()
  await f.redeem()
  await f.rotate("r0", "r1")
  await f.rotate("r1", "r2")
  assert.equal(await f.rotate("r0", "r3"), undefined)
  assert.ok(await f.rotate("r2", "r4"))
})

test("零宽限仍保留重放证据，而不是立即丢弃旧记录", async () => {
  const f = fixture()
  await f.issue()
  await f.redeem()
  assert.ok(await f.rotate("r0", "r1", { reuse: 0 }))
  assert.equal(await f.rotate("r0", "r2", { reuse: 0 }), undefined)
  assert.equal(await f.rotate("r1", "r3", { reuse: 0 }), undefined)
})

test("刷新族的绝对寿命不会随轮换延长", async () => {
  const f = fixture()
  await f.issue()
  await f.redeem()
  f.advance(590_000)
  assert.ok(await f.rotate())
  f.advance(10_000)
  assert.equal(await f.rotate("r1", "r2"), undefined)
})

test("修改账号版本之前已经验证过的密码不能再签发授权码", async () => {
  const f = fixture()
  await f.credential()
  await f.begin()
  await f.verify()
  assert.equal(await f.complete(), true)
  assert.equal(await f.issue("stale-login", { account: "account", version: 1 }), false)
  assert.equal(await f.redeem("stale-login"), undefined)
  assert.equal(await f.issue("fresh-login", { account: "account", version: 2 }), true)
})

test("重置事务成功完成后不能再次消费", async () => {
  const f = fixture()
  await f.credential()
  assert.equal(await f.begin(), "ok")
  assert.equal((await f.verify()).ok, true)
  assert.equal(await f.complete(), true)
  assert.equal(await f.complete(), false)
  assert.equal((await f.store.execute("getCredential", { account: "account" }))?.hash, "new-hash")
})

test("多个并发改密请求只有一次成功", async () => {
  const f = fixture()
  await f.credential()
  await f.begin()
  await f.verify()
  const completed = await Promise.all(Array.from({ length: 10 }, (_, i) => f.complete("flow", `hash-${i}`)))
  assert.equal(completed.filter(Boolean).length, 1)
  assert.equal((await f.store.execute("getCredential", { account: "account" }))?.version, 2)
})

test("五次错误验证码后，旧 Cookie 加正确验证码也不能恢复事务", async () => {
  const f = fixture()
  await f.credential()
  await f.begin()
  for (let i = 0; i < 5; i++) assert.equal((await f.verify("wrong")).ok, false)
  assert.equal((await f.verify()).ok, false)
  assert.equal(await f.complete(), false)
})

test("错误验证码次数被事务提交，不能并发绕过预算", async () => {
  const f = fixture()
  await f.credential()
  await f.begin()
  await Promise.all(Array.from({ length: 20 }, () => f.verify("wrong")))
  assert.equal((await f.verify()).ok, false)
})

test("验证码和已验证的重置状态都遵守同一个固定截止时间", async () => {
  const f = fixture()
  await f.credential()
  await f.begin()
  f.advance(599_000)
  assert.equal((await f.verify()).ok, true)
  f.advance(1000)
  assert.equal(await f.complete(), false)
})

test("重新发码立即使旧事务失效", async () => {
  const f = fixture()
  await f.credential()
  await f.begin()
  f.advance(60_000)
  assert.equal(await f.begin("reset", "replacement"), "ok")
  assert.equal((await f.verify("code-proof", "flow")).ok, false)
  assert.equal((await f.verify("code-proof", "replacement")).ok, true)
})

test("发送频率按账号限制，换 Cookie 不能绕过", async () => {
  const f = fixture()
  await f.credential()
  assert.equal(await f.begin(), "ok")
  assert.equal(await f.begin("reset", "immediate"), "limited")
  for (let i = 1; i < 5; i++) {
    f.advance(60_000)
    assert.equal(await f.begin("reset", `flow-${i}`), "ok")
  }
  f.advance(60_000)
  assert.equal(await f.begin("reset", "sixth"), "limited")
})

test("不同用途和不同 CSRF token 不能共用重置状态", async () => {
  const f = fixture()
  await f.credential()
  await f.begin()
  assert.equal((await f.store.execute("verifyFlow", {
    flowID: "flow", csrfHash: "wrong", codeHash: "code-proof",
  })).ok, false)
  assert.equal(await f.complete(), false)
  assert.equal((await f.verify()).ok, true)
})

test("注册时原子创建密码记录，注册状态不能用于重置已有账号", async () => {
  const f = fixture()
  assert.equal(await f.begin("register", "signup", { passwordHash: "signup-hash" }), "ok")
  const verified = await f.verify("code-proof", "signup")
  assert.equal(verified.ok, true)
  assert.deepEqual(verified.ok && verified.credential, { account: "account", version: 1 })
  assert.equal(await f.complete("signup"), false)
  assert.equal((await f.verify("code-proof", "signup")).ok, false)
  f.advance(60_000)
  assert.equal(await f.begin("register", "again", { passwordHash: "overwrite" }), "ok")
  assert.deepEqual(await f.verify("code-proof", "again"), { ok: false, reason: "exists" })
  assert.equal((await f.store.execute("getCredential", { account: "account" }))?.hash, "signup-hash")
})

test("注册重新发码保留服务端哈希，不接受浏览器提供的旧状态", async () => {
  const f = fixture()
  await f.begin("register", "first", { passwordHash: "signup-hash" })
  f.advance(60_000)
  assert.equal(await f.begin("register", "second", { previousFlowID: "first" }), "ok")
  assert.equal((await f.verify("code-proof", "first")).ok, false)
  assert.equal((await f.verify("code-proof", "second")).ok, true)
  assert.equal((await f.store.execute("getCredential", { account: "account" }))?.hash, "signup-hash")
})

test("账号不存在时重置不能创建密码账户", async () => {
  const f = fixture()
  await f.begin()
  await f.verify()
  assert.equal(await f.complete(), false)
  assert.equal(await f.store.execute("getCredential", { account: "account" }), undefined)
})

test("旧 KV 哈希的并发导入不能覆盖已经修改的新密码", async () => {
  const f = fixture()
  await f.credential()
  await f.begin()
  await f.verify()
  await f.complete()
  const imported = await f.credential()
  assert.equal(imported.hash, "new-hash")
  assert.equal(imported.version, 2)
})

test("注册后立即改密可以撤销关联的授权码和刷新会话", async () => {
  const f = fixture()
  await f.begin("register", "signup", { passwordHash: "signup-hash" })
  const result = await f.verify("code-proof", "signup")
  if (!result.ok || !result.credential) throw new Error("Registration failed")
  await f.issue("first", result.credential)
  await f.redeem("first")
  f.advance(60_000)
  await f.issue("pending", result.credential)
  await f.begin()
  await f.verify()
  await f.complete()
  assert.equal(await f.rotate(), undefined)
  assert.equal(await f.redeem("pending"), undefined)
})

test("同一账号绑定的多个实际 subject 都会被改密撤销", async () => {
  const f = fixture()
  await f.credential()
  await f.issue("one", { account: "account", version: 1 })
  await f.redeem("one")
  f.grant.subject = "custom:subject"
  await f.issue("two", { account: "account", version: 1 })
  await f.redeem("two", "family2")
  await f.begin()
  await f.verify()
  await f.complete()
  assert.equal(await f.rotate(), undefined)
  assert.equal(await f.rotate("r0", "r1", { familyID: "family2" }), undefined)
})

test("账号登录失败预算在窗口内不能通过新建事务绕过", async () => {
  const f = fixture()
  for (let i = 0; i < 10; i++) assert.equal(await f.store.execute("loginAttempt", { account: "account" }), true)
  assert.equal(await f.store.execute("loginAttempt", { account: "account" }), false)
  f.advance(15 * 60_000)
  assert.equal(await f.store.execute("loginAttempt", { account: "account" }), true)
})

test("成功登录仅在密码版本仍有效时清除失败预算", async () => {
  const f = fixture()
  await f.credential()
  for (let i = 0; i < 10; i++) await f.store.execute("loginAttempt", { account: "account" })
  assert.equal(await f.store.execute("finishLogin", { account: "account", version: 9 }), false)
  assert.equal(await f.store.execute("loginAttempt", { account: "account" }), false)
  assert.equal(await f.store.execute("finishLogin", { account: "account", version: 1 }), true)
  assert.equal(await f.store.execute("loginAttempt", { account: "account" }), true)
})

const signing = (id: string): SecurityKey => ({
  id, alg: "ES256", created: 1, privateKey: "test-private", publicKey: "test-public",
})

test("并发密钥初始化只保留一把活动密钥", async () => {
  const f = fixture()
  const results = await Promise.all(Array.from({ length: 10 }, (_, i) =>
    f.store.execute("ensureKey", { purpose: "signing", candidate: signing(`key-${i}`) }),
  ))
  assert.ok(results.every((keys) => keys.length === 1 && keys[0].id === results[0][0].id))
})

test("密钥轮换只在重叠期保留旧验证密钥", async () => {
  const f = fixture()
  await f.store.execute("ensureKey", { purpose: "signing", candidate: signing("old") })
  const keys = await f.store.execute("rotateKey", { purpose: "signing", candidate: signing("new"), overlap: 60 })
  assert.equal(keys.find((key) => key.id === "new")?.expired, undefined)
  assert.ok(keys.find((key) => key.id === "old")?.expired)
  f.advance(60_000)
  assert.deepEqual((await f.store.execute("listKeys", { purpose: "signing" })).map((key) => key.id), ["new"])
})

test("密钥撤销从权威列表移除，错误算法不会写入", async () => {
  const f = fixture()
  await f.store.execute("ensureKey", { purpose: "signing", candidate: signing("old") })
  await assert.rejects(f.store.execute("ensureKey", { purpose: "encryption", candidate: signing("wrong") }))
  assert.deepEqual(await f.store.execute("listKeys", { purpose: "encryption" }), [])
  await f.store.execute("revokeKey", { purpose: "signing", id: "old" })
  assert.deepEqual(await f.store.execute("listKeys", { purpose: "signing" }), [])
})

test("事务异常不提交之前已经执行的删除", async () => {
  const f = fixture()
  await f.issue("one")
  await f.redeem("one", "occupied")
  await f.issue("two")
  await assert.rejects(f.redeem("two", "occupied"))
  assert.ok(await f.redeem("two", "available"))
})
