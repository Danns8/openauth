import type { SecurityStorage } from "./security.js"

export interface StorageAdapter {
  get(key: string[]): Promise<Record<string, any> | undefined>
  remove(key: string[]): Promise<void>
  set(key: string[], value: any, expiry?: Date): Promise<void>
  scan(prefix: string[]): AsyncIterable<[string[], any]>
  /** 仅内存适配器提供同进程测试事务；分布式部署必须显式配置权威存储。 */
  security?: SecurityStorage
}

const SEPERATOR = String.fromCharCode(0x1f)

export function joinKey(key: string[]) {
  return key.join(SEPERATOR)
}

export function splitKey(key: string) {
  return key.split(SEPERATOR)
}

export namespace Storage {
  function encode(key: string[]) {
    return key.map((k) => k.replaceAll(SEPERATOR, ""))
  }
  export function get<T>(adapter: StorageAdapter, key: string[]) {
    return adapter.get(encode(key)) as Promise<T | null>
  }

  export function set(
    adapter: StorageAdapter,
    key: string[],
    value: any,
    ttl?: number,
  ) {
    if (ttl !== undefined && (!Number.isSafeInteger(ttl) || ttl < 0 ||
        !Number.isSafeInteger(Date.now() + ttl * 1000))) {
      throw new Error("Invalid storage TTL")
    }
    // 零表示立即失效，只有 undefined 才表示永久记录。
    if (ttl === 0) return adapter.remove(encode(key))
    const expiry = ttl === undefined ? undefined : new Date(Date.now() + ttl * 1000)
    return adapter.set(encode(key), value, expiry)
  }

  export function remove(adapter: StorageAdapter, key: string[]) {
    return adapter.remove(encode(key))
  }

  export function scan<T>(
    adapter: StorageAdapter,
    key: string[],
  ): AsyncIterable<[string[], T]> {
    return adapter.scan(encode(key))
  }
}
