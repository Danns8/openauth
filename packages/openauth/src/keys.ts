import {
  exportJWK,
  exportPKCS8,
  exportSPKI,
  generateKeyPair,
  importPKCS8,
  importSPKI,
  JWK,
  KeyLike,
} from "jose"
import { Storage, StorageAdapter } from "./storage/storage.js"
import type { SecurityKey, SecurityStorage } from "./storage/security.js"

const signingAlg = "ES256"
const encryptionAlg = "RSA-OAEP-512"

interface SerializedKeyPair {
  id: string
  publicKey: string
  privateKey: string
  created: number
  alg: string
  expired?: number
}

export interface KeyPair {
  id: string
  alg: string
  public: KeyLike
  private: KeyLike
  created: Date
  expired?: Date
  jwk: JWK
}

/**
 * @deprecated use `signingKeys` instead
 */
export async function legacySigningKeys(
  storage: StorageAdapter,
): Promise<KeyPair[]> {
  const alg = "RS512"
  const results = [] as KeyPair[]
  const scanner = Storage.scan<SerializedKeyPair>(storage, ["oauth:key"])
  for await (const [_key, value] of scanner) {
    const publicKey = await importSPKI(value.publicKey, alg, {
      extractable: true,
    })
    const privateKey = await importPKCS8(value.privateKey, alg)
    const jwk = await exportJWK(publicKey)
    jwk.kid = value.id
    results.push({
      id: value.id,
      alg,
      created: new Date(value.created),
      public: publicKey,
      private: privateKey,
      expired: new Date(1735858114000),
      jwk,
    })
  }
  return results
}

export async function signingKeys(storage: StorageAdapter, security?: SecurityStorage): Promise<KeyPair[]> {
  if (security) return authorityKeys(security, "signing")
  const results = [] as KeyPair[]
  const scanner = Storage.scan<SerializedKeyPair>(storage, ["signing:key"])
  for await (const [_key, value] of scanner) {
    const publicKey = await importSPKI(value.publicKey, value.alg, {
      extractable: true,
    })
    const privateKey = await importPKCS8(value.privateKey, value.alg)
    const jwk = await exportJWK(publicKey)
    jwk.kid = value.id
    jwk.use = "sig"
    results.push({
      id: value.id,
      alg: signingAlg,
      created: new Date(value.created),
      expired: value.expired ? new Date(value.expired) : undefined,
      public: publicKey,
      private: privateKey,
      jwk,
    })
  }
  results.sort((a, b) => b.created.getTime() - a.created.getTime())
  if (results.filter((item) => !item.expired).length) return results

  const key = await generateKeyPair(signingAlg, {
    extractable: true,
  })
  const serialized: SerializedKeyPair = {
    id: crypto.randomUUID(),
    publicKey: await exportSPKI(key.publicKey),
    privateKey: await exportPKCS8(key.privateKey),
    created: Date.now(),
    alg: signingAlg,
  }
  await Storage.set(storage, ["signing:key", serialized.id], serialized)
  return signingKeys(storage)
}

export async function encryptionKeys(
  storage: StorageAdapter,
  security?: SecurityStorage,
): Promise<KeyPair[]> {
  if (security) return authorityKeys(security, "encryption")
  const results = [] as KeyPair[]
  const scanner = Storage.scan<SerializedKeyPair>(storage, ["encryption:key"])
  for await (const [_key, value] of scanner) {
    const publicKey = await importSPKI(value.publicKey, value.alg, {
      extractable: true,
    })
    const privateKey = await importPKCS8(value.privateKey, value.alg)
    const jwk = await exportJWK(publicKey)
    jwk.kid = value.id
    results.push({
      id: value.id,
      alg: encryptionAlg,
      created: new Date(value.created),
      expired: value.expired ? new Date(value.expired) : undefined,
      public: publicKey,
      private: privateKey,
      jwk,
    })
  }
  results.sort((a, b) => b.created.getTime() - a.created.getTime())
  if (results.filter((item) => !item.expired).length) return results

  const key = await generateKeyPair(encryptionAlg, {
    extractable: true,
  })
  const serialized: SerializedKeyPair = {
    id: crypto.randomUUID(),
    publicKey: await exportSPKI(key.publicKey),
    privateKey: await exportPKCS8(key.privateKey),
    created: Date.now(),
    alg: encryptionAlg,
  }
  await Storage.set(storage, ["encryption:key", serialized.id], serialized)
  return encryptionKeys(storage)
}

async function generateSerializedKey(purpose: "signing" | "encryption"): Promise<SecurityKey> {
  const alg = purpose === "signing" ? signingAlg : encryptionAlg
  const pair = await generateKeyPair(alg, { extractable: true })
  return {
    id: crypto.randomUUID(), alg, created: Date.now(),
    publicKey: await exportSPKI(pair.publicKey),
    privateKey: await exportPKCS8(pair.privateKey),
  }
}

async function importAuthorityKeys(values: SecurityKey[], purpose: "signing" | "encryption") {
  const keys = await Promise.all(values.map(async (value): Promise<KeyPair> => {
    const alg = purpose === "signing" ? signingAlg : encryptionAlg
    if (value.alg !== alg) throw new Error("Unexpected key algorithm")
    const publicKey = await importSPKI(value.publicKey, alg, { extractable: true })
    const privateKey = await importPKCS8(value.privateKey, alg)
    const jwk = await exportJWK(publicKey)
    jwk.kid = value.id
    if (purpose === "signing") jwk.use = "sig"
    return {
      id: value.id, alg, public: publicKey, private: privateKey,
      created: new Date(value.created),
      expired: value.expired === undefined ? undefined : new Date(value.expired),
      jwk,
    }
  }))
  return keys.sort((a, b) => b.created.getTime() - a.created.getTime())
}

async function authorityKeys(security: SecurityStorage, purpose: "signing" | "encryption") {
  let values = await security.execute("listKeys", { purpose })
  if (!values.some((value) => value.expired === undefined)) {
    values = await security.execute("ensureKey", {
      purpose, candidate: await generateSerializedKey(purpose),
    })
  }
  return importAuthorityKeys(values, purpose)
}

/**
 * 仅在受信任的运维入口调用。重叠期需覆盖最长凭据寿命和缓存传播时间。
 * 不要为此函数创建无需管理员认证的公共路由。
 */
export async function rotateKeys(
  security: SecurityStorage,
  purpose: "signing" | "encryption",
  overlap: number,
): Promise<KeyPair[]> {
  const values = await security.execute("rotateKey", {
    purpose, candidate: await generateSerializedKey(purpose), overlap,
  })
  return importAuthorityKeys(values, purpose)
}
