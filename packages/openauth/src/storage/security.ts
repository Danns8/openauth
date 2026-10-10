/**
 * 认证事务只允许在一个权威存储中执行。
 * 回调内不得发送邮件或请求外部服务；失败次数必须提交，不能通过抛错回滚。
 */
export interface SecurityTransaction {
  get<T>(key: string): T | undefined
  put(key: string, value: unknown, expiresAt?: number): void
  remove(key: string): void
}

export interface Grant {
  type: string
  properties: unknown
  subject: string
  clientID: string
  ttl: { access: number; refresh: number }
}

export interface Credential {
  hash: unknown
  version: number
  subjects: string[]
}

export interface CredentialProof {
  account: string
  version: number
}

interface Session extends Grant {
  epoch: number
}

interface Family {
  grant: Session
  currentHash: string
  expiresAt: number
  revoked?: boolean
}

interface Flow {
  kind: "register" | "reset"
  account: string
  email: string
  csrfHash: string
  codeHash: string
  passwordHash?: unknown
  credentialVersion: number
  phase: "code" | "update"
  attempts: number
  maxAttempts: number
  expiresAt: number
}

export interface FlowView {
  kind: Flow["kind"]
  account: string
  email: string
  phase: Flow["phase"]
  expiresAt: number
}

type FlowResult =
  | { ok: false; reason?: "exists" }
  | { ok: true; kind: Flow["kind"]; email: string; credential?: CredentialProof }

export interface SecurityKey {
  id: string
  publicKey: string
  privateKey: string
  created: number
  alg: string
  expired?: number
  verifyUntil?: number
}

export interface SecurityOperations {
  listKeys: [{ purpose: "signing" | "encryption" }, SecurityKey[]]
  ensureKey: [{ purpose: "signing" | "encryption"; candidate: SecurityKey }, SecurityKey[]]
  rotateKey: [{
    purpose: "signing" | "encryption"; candidate: SecurityKey; overlap: number
  }, SecurityKey[]]
  revokeKey: [{ purpose: "signing" | "encryption"; id: string }, true]
  issueCode: [{
    codeHash: string
    grant: Grant
    redirectURI: string
    challenge: string
    credential?: CredentialProof
  }, boolean]
  redeemCode: [{
    codeHash: string
    clientID: string
    redirectURI: string
    challenge: string
    familyID: string
    refreshHash: string
  }, Session | undefined]
  createSession: [{
    grant: Grant
    familyID: string
    refreshHash: string
  }, Session]
  rotate: [{
    familyID: string
    tokenHash: string
    clientID: string
    successorHash: string
    successorCiphertext: string
    reuse: number
  }, { grant: Session; tokenCiphertext: string; timeUsed: number } | undefined]
  revokeSubject: [{ subject: string }, true]
  getCredential: [{ account: string }, Credential | undefined]
  importCredential: [{ account: string; hash: unknown }, Credential]
  loginAttempt: [{ account: string }, boolean]
  finishLogin: [CredentialProof, boolean]
  beginFlow: [{
    flowID: string
    kind: Flow["kind"]
    account: string
    email: string
    csrfHash: string
    codeHash: string
    passwordHash?: unknown
    previousFlowID?: string
  }, "ok" | "limited" | "exists" | "invalid"]
  getFlow: [{ flowID: string; csrfHash: string }, FlowView | undefined]
  verifyFlow: [{ flowID: string; csrfHash: string; codeHash: string }, FlowResult]
  completeReset: [{
    flowID: string
    csrfHash: string
    passwordHash: unknown
  }, boolean]
}

export interface SecurityStorage {
  execute<K extends keyof SecurityOperations>(
    operation: K,
    input: SecurityOperations[K][0],
  ): Promise<SecurityOperations[K][1]>
}

export const securityOperations = new Set<keyof SecurityOperations>([
  "listKeys", "ensureKey", "rotateKey", "revokeKey",
  "issueCode", "redeemCode", "createSession", "rotate", "revokeSubject",
  "getCredential", "importCredential", "loginAttempt", "finishLogin",
  "beginFlow", "getFlow", "verifyFlow", "completeReset",
])

function key(...parts: string[]) {
  // JSON 编码保留分隔符，避免不同账号或令牌映射到同一个存储键。
  return JSON.stringify(parts)
}

function deadline(now: number, seconds: number) {
  if (!Number.isSafeInteger(seconds) || seconds <= 0 ||
      !Number.isSafeInteger(now + seconds * 1000)) {
    throw new Error("Invalid security lifetime")
  }
  return now + seconds * 1000
}

/**
 * 此函数必须整体放在事务中；不能仅将其中的 put 单独串行化。
 * 参数只由持有存储绑定的 issuer 生成，不能把此接口暴露为公共 HTTP API。
 */
export function runSecurityOperation<K extends keyof SecurityOperations>(
  tx: SecurityTransaction,
  operation: K,
  input: SecurityOperations[K][0],
  now = Date.now(),
): SecurityOperations[K][1] {
  const args = input as any
  const epoch = (subject: string) => tx.get<number>(key("epoch", subject)) ?? 0
  const revoke = (subject: string) => {
    const next = epoch(subject) + 1
    if (!Number.isSafeInteger(next)) throw new Error("Invalid session epoch")
    tx.put(key("epoch", subject), next)
  }
  const openFamily = (grant: Session, familyID: string, refreshHash: string) => {
    deadline(now, grant.ttl.access)
    const expiresAt = deadline(now, grant.ttl.refresh)
    if (tx.get(key("family", familyID))) throw new Error("Duplicate session ID")
    tx.put(key("family", familyID), { grant, currentHash: refreshHash, expiresAt }, expiresAt)
  }
  const flowKey = (id: string) => key("flow", id)
  const activeKey = (flow: Flow) => key("active-flow", flow.kind, flow.account)
  const loadFlow = (id: string, csrfHash: string) => {
    const flow = tx.get<Flow>(flowKey(id))
    if (!flow || flow.expiresAt <= now || flow.csrfHash !== csrfHash ||
        tx.get<string>(activeKey(flow)) !== id) return
    return flow
  }
  const removeFlow = (id: string, flow: Flow) => {
    tx.remove(flowKey(id))
    if (tx.get<string>(activeKey(flow)) === id) tx.remove(activeKey(flow))
  }

  let result: unknown
  switch (operation) {
    case "listKeys":
    case "ensureKey":
    case "rotateKey":
    case "revokeKey": {
      if (args.purpose !== "signing" && args.purpose !== "encryption") {
        throw new Error("Invalid key purpose")
      }
      const storeKey = key("keys", args.purpose)
      let keys = (tx.get<SecurityKey[]>(storeKey) ?? []).filter(
        (item) => item.verifyUntil === undefined || item.verifyUntil > now,
      )
      if (operation === "revokeKey") {
        keys = keys.filter((item) => item.id !== args.id)
      } else if (operation !== "listKeys") {
        const candidate = args.candidate as SecurityKey
        const expected = args.purpose === "signing" ? "ES256" : "RSA-OAEP-512"
        if (!candidate?.id || candidate.alg !== expected ||
            !candidate.privateKey || !candidate.publicKey) throw new Error("Invalid key")
        if (operation === "rotateKey") {
          if (!Number.isSafeInteger(args.overlap) || args.overlap < 0 ||
              !Number.isSafeInteger(now + args.overlap * 1000)) throw new Error("Invalid overlap")
          keys = keys.map((item) => item.expired !== undefined ? item : {
            ...item, expired: now, verifyUntil: now + args.overlap * 1000,
          })
        }
        if (!keys.some((item) => item.expired === undefined)) {
          // 多个 Worker 同时初始化时只接纳一把活动密钥，失败竞争者读取已提交结果。
          keys.push({
            id: candidate.id, alg: candidate.alg, publicKey: candidate.publicKey,
            privateKey: candidate.privateKey, created: now,
          })
        }
      }
      tx.put(storeKey, keys)
      result = operation === "revokeKey" ? true : keys
      break
    }
    case "issueCode": {
      const grant = args.grant as Grant
      deadline(now, grant.ttl.access)
      deadline(now, grant.ttl.refresh)
      if (args.credential) {
        const proof = args.credential as CredentialProof
        const credential = tx.get<Credential>(key("credential", proof.account))
        if (!credential || credential.version !== proof.version) { result = false; break }
        if (!credential.subjects.includes(grant.subject)) {
          // 账号绑定必须保留所有已签发身份，否则改密可能漏掉旧会话。
          if (credential.subjects.length >= 1024) throw new Error("Too many account subjects")
          credential.subjects.push(grant.subject)
          tx.put(key("credential", proof.account), credential)
        }
      }
      if (tx.get(key("code", args.codeHash))) throw new Error("Duplicate authorization code")
      const expiresAt = now + 60_000
      tx.put(key("code", args.codeHash), {
        grant: { ...grant, epoch: epoch(grant.subject) },
        redirectURI: args.redirectURI, challenge: args.challenge, expiresAt,
      }, expiresAt)
      result = true
      break
    }
    case "redeemCode": {
      const codeKey = key("code", args.codeHash)
      const code = tx.get<{
        grant: Session; redirectURI: string; challenge: string; expiresAt: number
      }>(codeKey)
      if (!code || code.expiresAt <= now ||
          code.grant.clientID !== args.clientID ||
          code.redirectURI !== args.redirectURI || code.challenge !== args.challenge ||
          code.grant.epoch !== epoch(code.grant.subject)) break
      // 消费授权码和建立刷新族必须一起提交，禁止出现两套独立的后继凭据。
      tx.remove(codeKey)
      openFamily(code.grant, args.familyID, args.refreshHash)
      result = code.grant
      break
    }
    case "createSession": {
      const grant = { ...args.grant, epoch: epoch(args.grant.subject) } as Session
      openFamily(grant, args.familyID, args.refreshHash)
      result = grant
      break
    }
    case "rotate": {
      if (!Number.isSafeInteger(args.reuse) || args.reuse < 0) throw new Error("Invalid reuse window")
      const familyKey = key("family", args.familyID)
      const family = tx.get<Family>(familyKey)
      if (!family || family.revoked || family.expiresAt <= now ||
          family.grant.clientID !== args.clientID ||
          family.grant.epoch !== epoch(family.grant.subject)) break
      const usedKey = key("used", args.familyID, args.tokenHash)
      if (family.currentHash === args.tokenHash) {
        const used = {
          timeUsed: now,
          successorHash: args.successorHash,
          tokenCiphertext: args.successorCiphertext,
        }
        // 已使用记录保留到整个刷新族的绝对期限；retention 不能缩短重放证据寿命。
        tx.put(usedKey, used, family.expiresAt)
        family.currentHash = args.successorHash
        tx.put(familyKey, family, family.expiresAt)
        result = { grant: family.grant, tokenCiphertext: used.tokenCiphertext, timeUsed: now }
        break
      }
      const used = tx.get<{
        timeUsed: number; successorHash: string; tokenCiphertext: string
      }>(usedKey)
      if (!used) break
      if (now >= used.timeUsed + args.reuse * 1000) {
        family.revoked = true
        tx.put(familyKey, family, family.expiresAt)
      } else if (family.currentHash === used.successorHash) {
        result = {
          grant: family.grant, tokenCiphertext: used.tokenCiphertext, timeUsed: used.timeUsed,
        }
      }
      // 宽限内已被后续刷新超越的响应直接拒绝，不返回已经失效的后继令牌。
      break
    }
    case "revokeSubject":
      revoke(args.subject)
      result = true
      break
    case "getCredential":
      result = tx.get<Credential>(key("credential", args.account))
      break
    case "importCredential": {
      const credentialKey = key("credential", args.account)
      const existing = tx.get<Credential>(credentialKey)
      result = existing ?? { hash: args.hash, version: 1, subjects: [] }
      if (!existing) tx.put(credentialKey, result)
      break
    }
    case "loginAttempt": {
      const limitKey = key("login-limit", args.account)
      const limit = tx.get<{ count: number; expiresAt: number }>(limitKey) ??
        { count: 0, expiresAt: now + 15 * 60_000 }
      result = limit.count < 10
      if (result) {
        limit.count++
        tx.put(limitKey, limit, limit.expiresAt)
      }
      break
    }
    case "finishLogin": {
      const credential = tx.get<Credential>(key("credential", args.account))
      result = !!credential && credential.version === args.version
      if (result) tx.remove(key("login-limit", args.account))
      break
    }
    case "beginFlow": {
      const credential = tx.get<Credential>(key("credential", args.account))
      // 已注册和未注册邮箱都进入验证码流程，避免在验证邮箱归属前泄露账号是否存在。
      let passwordHash = args.passwordHash
      if (args.kind === "register" && passwordHash === undefined) {
        const previous = loadFlow(args.previousFlowID, args.csrfHash)
        if (!previous || previous.kind !== "register" || previous.account !== args.account) {
          result = "invalid"
          break
        }
        passwordHash = previous.passwordHash
      }
      const limitKey = key("send-limit", args.account)
      const limit = tx.get<{ count: number; last: number; expiresAt: number }>(limitKey) ??
        { count: 0, last: -Infinity, expiresAt: now + 60 * 60_000 }
      if (limit.count >= 5 || now - limit.last < 60_000) { result = "limited"; break }
      limit.count++
      limit.last = now
      tx.put(limitKey, limit, limit.expiresAt)
      const expiresAt = now + 10 * 60_000
      const flow: Flow = {
        kind: args.kind, account: args.account, email: args.email,
        csrfHash: args.csrfHash, codeHash: args.codeHash,
        passwordHash, credentialVersion: credential?.version ?? 0,
        phase: "code", attempts: 0, maxAttempts: 5, expiresAt,
      }
      const prior = tx.get<string>(activeKey(flow))
      if (prior) tx.remove(flowKey(prior))
      tx.put(flowKey(args.flowID), flow, expiresAt)
      tx.put(activeKey(flow), args.flowID, expiresAt)
      result = "ok"
      break
    }
    case "getFlow": {
      const flow = loadFlow(args.flowID, args.csrfHash)
      if (flow) {
        result = {
          kind: flow.kind, account: flow.account, email: flow.email,
          phase: flow.phase, expiresAt: flow.expiresAt,
        }
      }
      break
    }
    case "verifyFlow": {
      result = { ok: false }
      const flow = loadFlow(args.flowID, args.csrfHash)
      if (!flow || flow.phase !== "code") break
      flow.attempts++
      if (flow.codeHash !== args.codeHash) {
        if (flow.attempts >= flow.maxAttempts) removeFlow(args.flowID, flow)
        else tx.put(flowKey(args.flowID), flow, flow.expiresAt)
        break
      }
      const credentialKey = key("credential", flow.account)
      const credential = tx.get<Credential>(credentialKey)
      if ((credential?.version ?? 0) !== flow.credentialVersion) {
        removeFlow(args.flowID, flow)
        break
      }
      if (flow.kind === "reset") {
        flow.phase = "update"
        tx.put(flowKey(args.flowID), flow, flow.expiresAt)
        result = { ok: true, kind: flow.kind, email: flow.email }
      } else {
        if (credential || flow.passwordHash === undefined) {
          removeFlow(args.flowID, flow)
          result = credential ? { ok: false, reason: "exists" } : { ok: false }
          break
        }
        tx.put(credentialKey, { hash: flow.passwordHash, version: 1, subjects: [] })
        removeFlow(args.flowID, flow)
        result = {
          ok: true, kind: flow.kind, email: flow.email,
          credential: { account: flow.account, version: 1 },
        }
      }
      break
    }
    case "completeReset": {
      result = false
      const flow = loadFlow(args.flowID, args.csrfHash)
      if (!flow || flow.kind !== "reset" || flow.phase !== "update") break
      const credentialKey = key("credential", flow.account)
      const credential = tx.get<Credential>(credentialKey)
      if (!credential || credential.version !== flow.credentialVersion) {
        removeFlow(args.flowID, flow)
        break
      }
      // 密码版本、旧会话撤销和重置事务消费同一次提交，旧密码登录也会被版本检查拦截。
      credential.hash = args.passwordHash
      credential.version++
      if (!Number.isSafeInteger(credential.version)) throw new Error("Invalid credential version")
      for (const subject of credential.subjects) revoke(subject)
      tx.put(credentialKey, credential)
      removeFlow(args.flowID, flow)
      result = true
      break
    }
    default:
      throw new Error("Unknown security operation")
  }
  return result as SecurityOperations[K][1]
}

/** 仅用于单进程开发和测试；生产多实例不能用内存状态替代 Durable Object。 */
export function MemorySecurityStorage(now: () => number = () => Date.now()): SecurityStorage {
  let records = new Map<string, { value: unknown; expiresAt?: number }>()
  return {
    async execute(operation, input) {
      const time = now()
      const draft = new Map([...records].map(([name, record]) => [name, structuredClone(record)]))
      const tx: SecurityTransaction = {
        get<T>(name: string) {
          const record = draft.get(name)
          if (!record || (record.expiresAt !== undefined && record.expiresAt <= time)) return
          return structuredClone(record.value) as T
        },
        put(name, value, expiresAt) { draft.set(name, { value: structuredClone(value), expiresAt }) },
        remove(name) { draft.delete(name) },
      }
      const result = runSecurityOperation(tx, operation, input, time)
      for (const [name, record] of draft) {
        if (record.expiresAt !== undefined && record.expiresAt <= time) draft.delete(name)
      }
      records = draft
      return structuredClone(result)
    },
  }
}
