import type { DurableObjectNamespace, DurableObjectState } from "@cloudflare/workers-types"
import {
  runSecurityOperation, securityOperations,
  type SecurityOperations, type SecurityStorage, type SecurityTransaction,
} from "./security.js"

/**
 * 一个 issuer 使用一个固定名称的对象，账号、授权码和刷新族才能参加同一个事务。
 * name 不能来自请求参数；更改它会切换到另一份认证状态。
 */
export function DurableObjectSecurityStorage(options: {
  namespace: DurableObjectNamespace
  name: string
}): SecurityStorage {
  if (!options.name) throw new Error("Missing security namespace name")
  const stub = options.namespace.get(options.namespace.idFromName(options.name))
  return {
    async execute(operation, input) {
      const response = await stub.fetch("https://openauth-security.internal/operation", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ version: 1, operation, input }),
      })
      if (!response.ok) throw new Error("Security storage unavailable")
      const body = await response.json() as { ok?: boolean; result?: unknown }
      if (body.ok !== true) throw new Error("Invalid security storage response")
      // 不自动重试：响应丢失时事务可能已经提交，盲目重试会再次消费凭据。
      return body.result as any
    },
  }
}

/**
 * 必须以 SQLite 后端部署，且仅允许 issuer 通过内部绑定调用。
 * 不提供把用户请求原样转发至此对象的公共路由。
 */
export class OpenAuthSecurity {
  constructor(private readonly state: DurableObjectState) {
    state.storage.transactionSync(() => {
      state.storage.sql.exec(
        "CREATE TABLE IF NOT EXISTS openauth_security (key TEXT PRIMARY KEY, value TEXT NOT NULL, expires INTEGER)",
      )
      state.storage.sql.exec(
        "CREATE INDEX IF NOT EXISTS openauth_security_expiry ON openauth_security(expires)",
      )
    })
  }

  async fetch(request: Request): Promise<Response> {
    if (request.method !== "POST" || new URL(request.url).pathname !== "/operation") {
      return new Response("Not found", { status: 404 })
    }
    // 此接口只处理小型认证记录，避免异常调用占满单个对象内存。
    const reader = request.body?.getReader()
    if (!reader) return new Response("Invalid request", { status: 400 })
    const chunks: Uint8Array[] = []
    let size = 0
    while (true) {
      const chunk = await reader.read()
      if (chunk.done) break
      size += chunk.value.byteLength
      if (size > 256 * 1024) {
        await reader.cancel()
        return new Response("Request too large", { status: 413 })
      }
      chunks.push(chunk.value)
    }
    let body: { version: number; operation: keyof SecurityOperations; input: any }
    try {
      const bytes = new Uint8Array(size)
      let offset = 0
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength }
      body = JSON.parse(new TextDecoder().decode(bytes))
      if (body?.version !== 1 || !securityOperations.has(body.operation) ||
          !body.input || typeof body.input !== "object") throw new Error("Invalid operation")
    } catch {
      return new Response("Invalid operation", { status: 400 })
    }
    try {
      const now = Date.now()
      const result = this.state.storage.transactionSync(() => {
        const sql = this.state.storage.sql
        // 分批清理过期记录；安全期限由读取检查保证，不依赖清理任务准时执行。
        sql.exec(
          "DELETE FROM openauth_security WHERE key IN (SELECT key FROM openauth_security WHERE expires <= ? LIMIT 100)",
          now,
        )
        const tx: SecurityTransaction = {
          get<T>(key: string) {
            const row = sql.exec<{ value: string; expires: number | null }>(
              "SELECT value, expires FROM openauth_security WHERE key = ?", key,
            ).toArray()[0]
            if (!row || (row.expires !== null && row.expires <= now)) return
            return JSON.parse(row.value) as T
          },
          put(key, value, expiresAt) {
            sql.exec(
              "INSERT INTO openauth_security(key, value, expires) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, expires = excluded.expires",
              key, JSON.stringify(value), expiresAt ?? null,
            )
          },
          remove(key) { sql.exec("DELETE FROM openauth_security WHERE key = ?", key) },
        }
        return runSecurityOperation(tx, body.operation, body.input, now)
      })
      await this.state.storage.sync()
      return Response.json({ ok: true, result })
    } catch {
      // 不把密码哈希、验证码摘要、令牌或内部数据库异常发给调用方。
      return new Response("Security transaction failed", { status: 500 })
    }
  }
}
