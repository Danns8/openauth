# OpenAuth 安全修复与迁移说明

## 先看结论

本次在第一阶段修复之上补齐认证事务。Cloudflare 部署必须增加 SQLite 后端的
Durable Object；KV 继续存放普通业务记录，但不再保存可用于兑换的授权码、刷新
令牌状态、密码重置事务、活动密码或新签名密钥。

**旧会话需要重新登录。旧密码哈希需要在切换流量前显式迁移。**
本提交不会部署 Worker、修改现有绑定、删除 KV 数据或自动执行迁移。
不要直接回滚到旧的 KV 认证实现，否则旧凭据和已撤销会话可能重新生效。

第一阶段已经完成的精确回调注册、S256 PKCE、audience 校验、Provider 隔离及
本地 JSON 错误处理保持不变。本次没有升级依赖或修改业务账号标识的生成规则。

## 一、为什么增加 Durable Object

“先读取、后删除”无法保证授权码只被兑换一次；多个 Worker 可以同时读到旧值。
单进程锁也不能保护分布式部署。因此，账号安全版本、授权码、刷新族和重置事务
需要一起放在同一个可执行事务的权威存储中。

新增 `OpenAuthSecurity` 使用 SQLite 的同步事务。事务中只做状态检查和 SQL
读写，不发送邮件、不请求第三方服务。验证码失败次数通过返回失败结果提交，
不能抛异常让次数回滚。事务确认完成后才能返回成功。

一个 issuer 使用一个固定名称的 Durable Object。这是为了让密码更新、会话撤销
和重置事务消费可以在同一事务内完成，不是通用的跨对象事务机制。当前实现没有
按用户分片：单对象的吞吐、延迟和费用需要用真实负载验收，不适合不经压测直接
承诺大规模吞吐。名称和绑定必须来自受信任配置，不能由请求参数决定。

## 二、需要修改的部署配置

### 1. 导出 Durable Object 类

在已有 Worker 入口增加以下导出，不要另建公共转发接口：

```ts
export { OpenAuthSecurity } from "@openauthjs/openauth/storage/security-cloudflare"
```

普通导出类通过内部绑定提供 `fetch` 接口，不需要给它配置公网域名。
绝不能把收到的任意 HTTP 请求原样转发到该接口；它有读写密码哈希和密钥的权限。

### 2. 增加 SQLite 后端绑定

下面内容合并进现有 `wrangler.toml`，不要覆盖整个文件。绑定名、迁移标签应与
项目已有配置核对；示例不是当前生产配置。

```toml
[[durable_objects.bindings]]
name = "AUTH_SECURITY"
class_name = "OpenAuthSecurity"

[[migrations]]
tag = "openauth-security-v2"
new_sqlite_classes = ["OpenAuthSecurity"]
```

如果项目已经采用新版本 Wrangler 的 `exports` 配置，则在现有格式下声明
`OpenAuthSecurity` 的 `storage = "sqlite"`，不要混用两种生命周期管理方式。
这次不替你把整个项目的 `migrations` 改写成 `exports`。

保留并核对项目原有 `compatibility_date` 和 Node 兼容配置。Password 默认
Scrypt 依赖 `node:crypto`；当前没有提供完整 Wrangler 配置，必须在实际 Workers
环境确认。不要为通过构建擅自删除密码哈希或降低安全要求。

### 3. 为 issuer 传入认证事务存储

以下选项合并到现有完整初始化代码中。域名、客户端 ID、发送验证码函数、
subjects 和 success 必须使用你自己的配置。

```ts
import { issuer } from "@openauthjs/openauth"
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare"
import { DurableObjectSecurityStorage } from "@openauthjs/openauth/storage/security-cloudflare"

const storage = CloudflareStorage({ namespace: env.AUTH_KV })
const security = DurableObjectSecurityStorage({
  namespace: env.AUTH_SECURITY,
  name: "auth-production-v2",
})

const app = issuer({
  issuer: "https://auth.example.com",
  storage,
  security,
  clients: {
    web: {
      redirectURIs: ["https://web.example.com/auth/callback"],
      clientSecret: env.WEB_CLIENT_SECRET,
    },
    spa: {
      redirectURIs: ["https://app.example.com/auth/callback"],
    },
  },
  providers,
  subjects,
  success,
  ttl: {
    access: 15 * 60,
    refresh: 30 * 24 * 60 * 60,
    reuse: 60,
  },
})
```

`name` 和绑定变更会切换到另一份状态。不要每次部署生成随机名称。
认证存储不可用时请求失败，不回退到 KV 或每个 Worker 自己的内存状态。

`MemoryStorage()` 为现有单进程测试自动提供内存认证事务；它不是生产替代品。
即使启用普通记录的 `persist`，认证事务、密码和新密钥仍不恢复到文件，重启会
丢失这些开发状态。其他自定义适配器须显式传入 `security`。

## 三、旧密码迁移与切换顺序

已同意旧会话重新登录，因此不导入旧授权码、Refresh Token、重置事务和旧密钥。
用户密码不应因此丢失；密码哈希单独迁移：

1. 备份原 KV 并记录旧部署版本。在维护窗口暂停旧版本的注册、改密和登录写入，
   避免迁移期间旧版本仍修改密码。
2. 创建新 Durable Object 绑定，在仅管理员可执行的 Worker 管理环境中运行：

```ts
import { migratePasswordCredentials } from "@openauthjs/openauth/provider/password"

// storage 指向旧 KV，security 指向将要正式使用的固定 Durable Object。
// 第三个参数必须与 issuer.providers 的 Password 配置键一致。
const counts = await migratePasswordCredentials(storage, security, "password")
console.log(counts)
```

3. 函数只返回导入/跳过数量，不返回哈希。它只导入 `["email", email, "password"]`
   记录，不覆盖认证存储中已存在、尤其是已经改密的账号。
   旧邮箱存在空白、控制字符或大小写不一致时中止并要求人工处理，避免合并错账号。
   原部署使用自定义 hasher 的，切换后必须保留兼容的 hasher。
4. 用少量专用测试账号验证旧密码登录、改密、刷新撤销和新注册，再切换 issuer
   与各 Web/SPA SDK。清除应用自己的登录 Cookie/缓存，让旧会话重新认证。
5. 旧格式刷新令牌即使还在 KV 中也被拒绝；不自动重试成旧协议。
   新密钥与旧 KV 密钥隔离，旧 Access Token 需在各应用的旧 JWKS 缓存退出后拒绝。
6. 迁移完成后关闭管理入口。不要把迁移函数暴露为无认证的 HTTP 路由，也不要
   周期性把 KV 全量复制回来。本提交不会删除原数据，后续清理需要独立备份策略。

运行时 Password 路由不读取旧 KV 密码；这防止误配置或空的新命名空间让旧密码
自动“复活”。迁移统计假定维护窗口内单次执行；并发迁移不会覆盖已有账号，但
计数不用于证明并发迁移的精确覆盖率。

**回滚不是简单切回旧代码。**恢复旧数据库快照会恢复消费和撤销前的状态。
回滚或灾难恢复时必须重新评估密码版本，并整体失效恢复前会话及密钥；不能恢复
旧状态后继续接受外部持有的旧凭据。具体备份、权限和恢复操作仍需运维验收。

## 四、授权码、刷新和密码重置的变化

### 授权码

有效期仍为 60 秒。服务端检查 client、redirect URI、S256 和截止时间后，在一个
事务中消费授权码并建立唯一刷新族。错误参数不消费授权码；并发兑换最多一次成功。
事务提交后响应丢失可能要求用户重新登录，这是比重复签发更安全的失败方式。

### 刷新令牌

新的格式是供程序当作不透明字符串使用的 `v2` 凭据，客户端不要自行解析。
数据库保存令牌摘要；宽限内需要返回的同一后继令牌以 JWE 密文保存。

刷新族具有创建时确定的绝对期限，刷新不会把总寿命无限往后延长。已消费令牌的
重放证据保留到该族截止，旧的 `ttl.retention` 配置不再缩短证据寿命。

同一旧令牌在允许的并发宽限内返回同一个尚有效的后继。后继已被进一步刷新时，
拒绝旧响应而不返回已经失效的令牌。超过宽限重放一个已知旧令牌会撤销整个族；
未知随机令牌、错误 client ID 不会撤销别人会话。`reuse: 0` 仍保留重放证据。

### 密码流程

默认限制是：验证码事务 10 分钟、最多 5 次错误验证、每账号 60 秒发送间隔和
每小时最多 5 次发送；密码登录每账号每 15 分钟最多 10 次尝试。所有计数在
权威事务中提交，旧 Cookie 无法回退计数。重复发码使旧事务失效。

注册和重置使用不同用途的事务，Cookie 只放事务标识及 CSRF 随机值。验证码和
密码哈希保存在服务端；传给旧 UI 的 `state.code` 和 `state.password` 保留字段，
但值为空，不再提供秘密数据。注册只有证明邮箱归属后才提示账号已存在。

改密时同时更新密码版本、撤销该密码账号关联的所有实际 subject，并消费重置
事务。注册成功也会关联实际签发的 subject。改密前开始但尚未签发的密码登录，
会因版本不符而失败。旧重置 Cookie 无法第二次修改密码。

未提供自定义密码策略时，新密码最少 12 字符；所有新密码和登录密码上限 1024
字符。自定义 `validatePassword` 仍可设置业务规则，但异常一律拒绝。
账号级限制不能代替边缘 IP 限流、发送服务额度和防批量创建策略，生产应另行配置。

### Access Token 的撤销边界

本次保留 SDK 的本地 JWT 验证行为，**没有暗中加入每次请求的远程会话查询**。
改密会立即阻止旧授权码兑换和后续刷新；已经签发的新版本 Access Token 仍可能
有效到 `exp`。默认 Access Token TTL 未偷偷改变，仍为 30 天；生产示例改为
15 分钟，需要按业务明确设置。要求改密后 Access Token 立即失效的资源服务，
必须额外接入权威会话版本校验；本次没有声称解决这一额外需求。

## 五、客户端、CSRF 和页面

第一阶段的完整 URL 精确注册、默认拒绝、固定公共 issuer、强制 S256 保留。
客户端仍须保存每次登录的 state/verifier，并在回调先比较 state，再兑换授权码。
SDK 不替代应用自身的登录事务存储。

配置 `clients.web.clientSecret` 后，该客户端成为机密客户端，授权码兑换和刷新
必须通过 `client_secret_basic` 或 `client_secret_post` 认证。secret 至少 32 字符，
应由安全随机生成器产生并存在 Worker Secret 中。SPA 不设置 secret。
Web SDK 对应设置 `createClient({ clientID, issuer, clientSecret })`，它使用 Basic；
不得把包含 secret 的 SDK 实例打包进浏览器。

自定义 Password UI 的 login/register/change 回调新增最后一个可选参数
`csrfToken`；每个 POST 表单（包括重新发送验证码）必须放入：

```tsx
<input type="hidden" name="csrf" value={csrfToken} />
```

内置 PasswordUI 已经更新。服务端还检查 Origin；没有 Origin 的客户端仍须
提供正确的 CSRF token，不能仅凭缺少该头获得放行。改密返回地址只允许认证
站点同源地址，不再接受任意外部站点。

HTTPS 认证 Cookie 使用 `__Host-` 前缀、Secure、HttpOnly 和 Path=/。
删除时也带 Secure，避免浏览器拒绝删除。合法跨站 Provider 回调仍能使用
SameSite=None，Password 表单另行进行 CSRF 校验，不靠关闭跨站回调修复。

认证 HTML 默认禁止被 iframe 嵌入、禁止修改 base URL、禁止缓存并限制 Referer。
已有自定义 CSP 或 X-Frame-Options 不被覆盖，需确认自定义策略同样安全。
实际 CDN/代理可能覆盖响应头，仍要检查线上响应。

## 六、密钥轮换与缓存

新部署签名密钥与加密密钥从 Durable Object 获取，初始化竞争只接纳一把活动
密钥，避免不同 Worker 各自创建并缓存不同密钥。JWT 使用 ES256；
加密沿用 RSA-OAEP-512 / A256GCM。

受信任的运维环境可调用：

```ts
import { rotateKeys } from "@openauthjs/openauth/keys"

// 示例重叠期；必须按实际最长 Access Token 寿命和缓存传播时间计算。
await rotateKeys(security, "signing", 31 * 24 * 60 * 60)

// 加密重叠期至少覆盖登录/重置事务及刷新重试宽限。
await rotateKeys(security, "encryption", 24 * 60 * 60)
```

issuer 及 SDK 密钥缓存各最多 30 秒；未知 kid 至多触发一次受控重取，并有
5 秒冷却。不同层叠加可能使变更传播接近 60 秒；外部缓存必须遵守 no-store。
缓存加载失败不无限接受过期密钥。轮换后的旧密钥只保留到配置的重叠期；
直接撤销可通过受信任管理环境的 `security.execute("revokeKey", { purpose, id })`，
但同样存在上述缓存传播时间。不要把这些管理操作暴露给普通客户端。

轮换过渡中，缓存尚未刷新的 Worker 可能仍短暂使用旧活动密钥，因此重叠期
必须包含缓存时间。SDK 的算法允许列表不等于信任所有同算法密钥：仍必须来自
受信任 issuer 的 JWKS，且 audience、issuer、时间和 subject 校验全部通过。

## 七、普通 KV 的 TTL

普通 KV 新记录增加带版本的封装，在读取和扫描时检查应用层 expiresAt。
5 秒数据到第 5 秒即不可用，即使 KV 的物理清理至少需要 60 秒。
未设置 TTL 仍表示长期保存；TTL 为 0 表示删除；负数、非整数和溢出被拒绝。
旧的未封装普通记录继续可读；这不是对旧安全会话的兼容入口。

KV 的手动删除仍有分布式可见性限制。授权码、密码、撤销和限流不走该存储，
所以安全正确性不依赖 KV 删除及时传播。

## 八、测试命令和当前验证状态

```sh
# 仓库根目录；不允许安装时随意改写锁文件
bun install --frozen-lockfile
cd packages/openauth
bun run build
bun test

# 构建后，用 Node.js 22.16 或更高版本执行真实 SQLite 事务测试
node script/security-sqlite.mjs
```

新增测试：
- `test/security-transactions.test.ts`：32 项事务、并发、重放、限次及密码版本测试。
- `test/security-support.test.ts`：12 项客户端认证、缓存、来源、返回地址和 TTL 测试。
- `test/security-password.test.ts`：真实 Password/Hono 路由、改密、注册、CSRF 和
  显式迁移回归；测试使用假 hasher，只用于状态流转，不用于密码强度验收。
- `script/security-sqlite.mjs`：8 项对生产 Durable Object 类及 SQL 的测试，
  以 Node 内置 SQLite 和薄适配层模拟平台存储，包含重启持久化、事务回滚和
  提交后响应丢失。它不是在真正 Cloudflare 平台运行的结果。

当前编写环境没有 Bun，无法解析外部包仓库域名，没有安装完整项目依赖。
实际已运行的是前两组共 44 项测试（真实模块转译后仅切换测试运行器到
node:test），以及 8 项 SQLite 测试，全部通过；认证事务和辅助模块通过独立
strict TypeScript 检查，其余修改文件完成语法检查。

完整 Bun 构建/测试、全项目类型检查、真实 Workers/KV、浏览器和真实 GitHub
OAuth 流程尚未运行。第一阶段已有 SDK/Hono 测试也必须一起运行，不能只跑新增
用例就合并。测试脚本没有增加 npm 依赖，Node 的 SQLite 仅用于本地验证。

## 九、尚待部署验收的内容

- 实际 Worker 绑定、SQLite 后端、兼容日期/Node 标志和资源限制。
- 密码哈希迁移覆盖率及自定义 hasher 兼容性；旧会话全部重新登录。
- 真浏览器的 __Host- Cookie、CSRF、Provider 跳转和自定义 UI。
- 多请求、对象重启、上游超时、单对象负载与恢复演练。
- 生产依赖树、锁文件及完整漏洞扫描；本次没有盲目升级 package.json 或生成
  未实际解析过的 bun.lockb，也没有声称 npm audit 已通过。
- 未启用的 Code/OIDC Provider 的全部安全生命周期不属于本轮完成验收范围。
- 权限、Secret、IP/WAF 限流、日志脱敏和 Access Token 即时撤销要求。

只有完成上述构建和部署验收后，才应将 Draft PR 转为可合并版本并上线。
