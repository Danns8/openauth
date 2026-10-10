/**
 * 在 Node.js 22.16+ 中运行生产 Durable Object 类及真实 SQLite 语句。
 * 本脚本适配平台存储接口，不模拟 Cloudflare 调度、输出门或网络。
 * 先执行 bun run build，再执行 node script/security-sqlite.mjs。
 */
import assert from "node:assert/strict"
import { test } from "node:test"
import { DatabaseSync } from "node:sqlite"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { OpenAuthSecurity, DurableObjectSecurityStorage } from "../dist/esm/storage/security-cloudflare.js"

function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), "openauth-security-"))
  const filename = join(directory, "state.sqlite")
  let database
  let object
  let failSync = false
  const open = () => {
    database = new DatabaseSync(filename)
    const state = { storage: {
      sql: {
        exec(query, ...bindings) {
          const rows = database.prepare(query).all(...bindings)
          return { toArray: () => rows }
        },
      },
      transactionSync(callback) {
        database.exec("BEGIN IMMEDIATE")
        try {
          const result = callback()
          assert.ok(!result || typeof result.then !== "function")
          database.exec("COMMIT")
          return result
        } catch (error) {
          database.exec("ROLLBACK")
          throw error
        }
      },
      async sync() {
        if (failSync) throw new Error("测试提交响应丢失")
      },
    } }
    object = new OpenAuthSecurity(state)
  }
  open()
  t.after(() => { database.close(); rmSync(directory, { recursive: true, force: true }) })
  const storage = DurableObjectSecurityStorage({
    name: "test-issuer",
    namespace: {
      idFromName: (name) => name,
      get: (name) => {
        assert.equal(name, "test-issuer")
        return { fetch: (url, init) => object.fetch(new Request(url, init)) }
      },
    },
  })
  const grant = {
    type: "user", properties: { userID: "123" }, subject: "user:123",
    clientID: "web", ttl: { access: 60, refresh: 600 },
  }
  const issue = (codeHash = "code") => storage.execute("issueCode", {
    codeHash, grant, challenge: "challenge", redirectURI: "https://web.test/callback",
  })
  const redeem = (codeHash = "code", familyID = "family") => storage.execute("redeemCode", {
    codeHash, clientID: "web", redirectURI: "https://web.test/callback", challenge: "challenge",
    familyID, refreshHash: "r0",
  })
  const rotate = (tokenHash = "r0", successorHash = "r1") => storage.execute("rotate", {
    familyID: "family", clientID: "web", tokenHash, successorHash,
    successorCiphertext: "sealed-" + successorHash, reuse: 60,
  })
  return {
    storage, issue, redeem, rotate,
    raw: (request) => object.fetch(request),
    restart() { database.close(); open() },
    loseResponse(value) { failSync = value },
  }
}

test("SQLite 并发兑换同一授权码只提交一次", async (t) => {
  const f = fixture(t)
  await f.issue()
  const results = await Promise.all(Array.from({ length: 10 }, (_, i) => f.redeem("code", "family-" + i)))
  assert.equal(results.filter(Boolean).length, 1)
})

test("对象重建和数据库重开后仍记得授权码已消费", async (t) => {
  const f = fixture(t)
  await f.issue()
  await f.redeem()
  f.restart()
  assert.equal(await f.redeem(), undefined)
  assert.ok(await f.rotate())
})

test("SQLite 事务异常回滚已经执行的授权码删除", async (t) => {
  const f = fixture(t)
  await f.issue("first")
  await f.redeem("first", "occupied")
  await f.issue("second")
  await assert.rejects(f.redeem("second", "occupied"))
  assert.ok(await f.redeem("second", "available"))
})

test("提交后响应失败不会自动重试或重复签发", async (t) => {
  const f = fixture(t)
  await f.issue()
  f.loseResponse(true)
  await assert.rejects(f.redeem())
  f.loseResponse(false)
  assert.equal(await f.redeem(), undefined)
})

test("SQLite 中的旧令牌重放记录在对象重启后仍有效", async (t) => {
  const f = fixture(t)
  let now = 1_700_000_000_000
  t.mock.method(Date, "now", () => now)
  await f.issue()
  await f.redeem()
  await f.rotate()
  f.restart()
  now += 60_001
  assert.equal(await f.rotate("r0", "r2"), undefined)
  assert.equal(await f.rotate("r1", "r3"), undefined)
})

test("SQLite 改密完成后，重放旧事务无法再次写入", async (t) => {
  const f = fixture(t)
  await f.storage.execute("importCredential", { account: "account", hash: "old" })
  await f.storage.execute("beginFlow", {
    flowID: "reset", kind: "reset", account: "account", email: "test@example.test",
    csrfHash: "csrf", codeHash: "proof",
  })
  await f.storage.execute("verifyFlow", { flowID: "reset", csrfHash: "csrf", codeHash: "proof" })
  const input = { flowID: "reset", csrfHash: "csrf", passwordHash: "new" }
  const results = await Promise.all(Array.from({ length: 10 }, () => f.storage.execute("completeReset", input)))
  assert.equal(results.filter(Boolean).length, 1)
  f.restart()
  assert.equal(await f.storage.execute("completeReset", input), false)
  assert.equal((await f.storage.execute("getCredential", { account: "account" })).hash, "new")
})

test("错误验证码计数提交到 SQLite，而不是只存在内存里", async (t) => {
  const f = fixture(t)
  await f.storage.execute("beginFlow", {
    flowID: "reset", kind: "reset", account: "account", email: "test@example.test",
    csrfHash: "csrf", codeHash: "proof",
  })
  for (let i = 0; i < 5; i++) {
    await f.storage.execute("verifyFlow", { flowID: "reset", csrfHash: "csrf", codeHash: "wrong" })
    f.restart()
  }
  assert.equal((await f.storage.execute("verifyFlow", {
    flowID: "reset", csrfHash: "csrf", codeHash: "proof",
  })).ok, false)
})

test("非法内部操作和超大请求在执行事务之前被拒绝", async (t) => {
  const f = fixture(t)
  const send = (body) => f.raw(new Request("https://security.internal/operation", { method: "POST", body }))
  assert.equal((await send("{")).status, 400)
  assert.equal((await send(JSON.stringify({ version: 1, operation: "unknown", input: {} }))).status, 400)
  assert.equal((await send("x".repeat(256 * 1024 + 1))).status, 413)
  assert.equal((await f.raw(new Request("https://security.internal/operation"))).status, 404)
})
