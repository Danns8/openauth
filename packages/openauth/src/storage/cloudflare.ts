/**
 * Cloudflare KV 仅保存普通记录，不承担授权码消费或刷新轮换的事务。
 * 安全关键状态请同时配置 DurableObjectSecurityStorage。
 */
import type { KVNamespace } from "@cloudflare/workers-types"
import { joinKey, splitKey, StorageAdapter } from "./storage.js"

export interface CloudflareStorageOptions {
  namespace: KVNamespace
}

interface StoredValue {
  __openauth_storage: 2
  value: any
  expiresAt: number | null
}

function decode(value: any) {
  if (value?.__openauth_storage !== 2) return value
  if (value.expiresAt !== null &&
      (!Number.isSafeInteger(value.expiresAt) || value.expiresAt <= Date.now())) return
  return value.value
}

export function CloudflareStorage(
  options: CloudflareStorageOptions,
): StorageAdapter {
  return {
    async get(key: string[]) {
      const value = await options.namespace.get(joinKey(key), "json")
      if (value === null) return
      return decode(value)
    },

    async set(key: string[], value: any, expiry?: Date) {
      const expiresAt = expiry?.getTime() ?? null
      if (expiresAt !== null && !Number.isSafeInteger(expiresAt)) throw new Error("Invalid expiry")
      if (expiresAt !== null && expiresAt <= Date.now()) {
        await options.namespace.delete(joinKey(key))
        return
      }
      const stored: StoredValue = { __openauth_storage: 2, value, expiresAt }
      await options.namespace.put(joinKey(key), JSON.stringify(stored), {
        // KV 的物理清理下限为 60 秒；get 和 scan 独立执行应用层截止时间。
        expirationTtl: expiresAt === null ? undefined :
          Math.max(Math.ceil((expiresAt - Date.now()) / 1000), 60),
      })
    },

    async remove(key: string[]) {
      await options.namespace.delete(joinKey(key))
    },

    async *scan(prefix: string[]) {
      let cursor: string | undefined
      while (true) {
        const result = await options.namespace.list({
          prefix: joinKey([...prefix, ""]),
          cursor,
        })
        for (const key of result.keys) {
          const raw = await options.namespace.get(key.name, "json")
          if (raw === null) continue
          const value = decode(raw)
          if (value !== undefined) yield [splitKey(key.name), value]
        }
        if (result.list_complete) break
        cursor = result.cursor
      }
    },
  }
}
