<p align="center">
  <a href="https://openauth.js.org">
    <picture>
      <source srcset="https://raw.githubusercontent.com/toolbeam/identity/main/openauth/logo-dark.svg" media="(prefers-color-scheme: dark)">
      <source srcset="https://raw.githubusercontent.com/toolbeam/identity/main/openauth/logo-light.svg" media="(prefers-color-scheme: light)">
      <img src="https://raw.githubusercontent.com/toolbeam/identity/main/openauth/logo-light.svg" alt="OpenAuth logo">
    </picture>
  </a>
</p>
<p align="center">
  <a href="https://sst.dev/discord"><img alt="Discord" src="https://img.shields.io/discord/983865673656705025?style=flat-square&label=Discord" /></a>
  <a href="https://www.npmjs.com/package/@openauthjs/openauth"><img alt="npm" src="https://img.shields.io/npm/v/%40openauthjs%2Fcore?style=flat-square" /></a>
  <a href="https://github.com/toolbeam/openauth/actions/workflows/release.yml"><img alt="构建状态" src="https://img.shields.io/github/actions/workflow/status/toolbeam/openauth/release.yml?style=flat-square&branch=master" /></a>
</p>

---

[OpenAuth](https://openauth.js.org) 是一个基于标准的认证提供程序，适用于 Web 应用、移动应用、单页应用、API 或第三方客户端。它目前处于测试阶段。

- **通用**：你可以将它部署为独立服务，或嵌入现有应用。它可与任何框架或平台配合使用。
- **自托管**：它完全运行在你自己的基础设施上，可部署在 Node.js、Bun、AWS Lambda 或 Cloudflare Workers 上。
- **基于标准**：它实现 OAuth 2.0 规范，并基于 Web 标准。因此任何 OAuth 客户端都可以使用它。
- **可定制**：它附带预构建的可主题化 UI，你可以自定义或选择不用。

<picture>
  <source srcset="https://raw.githubusercontent.com/toolbeam/identity/main/openauth/assets/themes-dark.png" media="(prefers-color-scheme: dark)">
  <source srcset="https://raw.githubusercontent.com/toolbeam/identity/main/openauth/assets/themes-light.png" media="(prefers-color-scheme: dark)">
  <img src="https://raw.githubusercontent.com/toolbeam/identity/main/openauth/assets/themes-light.png" alt="OpenAuth 主题">
</picture>

## 快速开始

部署本仓库到 Cloudflare Workers，并通过 GitHub 自动构建，请参见 [Cloudflare 部署说明](cloudflare/README.md)。

如果你只想尽快上手，可以直接进入[代码示例](https://github.com/toolbeam/openauth/tree/master/examples)文件夹复制粘贴。还有 [SST 组件](https://sst.dev/docs/component/aws/auth) 可用于部署 OpenAuth 所需的一切。

## 理念

虽然有许多开源认证解决方案，但几乎都是要嵌入单个应用的库。集中式认证服务器通常作为 SaaS 服务提供——例如 Auth0 或 Clerk。

而 OpenAuth 是一个集中式认证服务器，运行在你自己的基础设施上，并为易于自托管而设计。它可以用来认证你所有的应用——Web 应用、移动应用、内部管理工具等。

它大体遵循 OAuth 2.0 规范——这意味着任何能使用 OAuth 的东西都可以用它来接收访问令牌和刷新令牌。当客户端发起授权流程时，OpenAuth 会交给已配置的某个提供程序——这可以是 Google、GitHub 等第三方身份提供商，也可以是电子邮件/密码或 PIN 码等内置流程。

由于遵循这些规范，它甚至可以用于为第三方应用签发凭证——让你实现“使用 myapp 登录”流程。

OpenAuth 有意不尝试解决用户管理。我们发现，鉴于 JS 生态中使用的数据库和驱动种类繁多，这是一个非常困难的问题。此外，要构建适用于所有用例的数据抽象也相当困难。相反，一旦用户表明了自己的身份，OpenAuth 会调用一个回调，你可以在其中实现自己的用户查找/创建逻辑。

虽然 OpenAuth 尽量做到无状态，但它确实需要存储少量数据（刷新令牌、密码哈希等）。不过，这已被简化为一个简单的 KV 存储，并针对 Cloudflare KV 和 DynamoDB 等零开销系统提供了多种实现。你永远不需要直接访问其中存储的任何数据。

还有一个可主题化的 UI，你可以用它来快速开始，而无需自己实现任何设计。它构建在更底层的系统之上，因此你可以复制粘贴默认 UI 并进行调整，或者完全不用它，实现自己的 UI。

最后，OpenAuth 由 [SST](https://sst.dev) 的维护者创建，SST 是一个管理应用所有基础设施的工具。它包含用于 OpenAuth 的组件，使部署到 AWS 或 Cloudflare 尽可能简单。

## 教程

我们将展示如何部署认证服务器，然后展示一个使用它的示例应用。

### 认证服务器

首先从 `@openauthjs/openauth` 包中导入 `issuer` 函数。

```ts
import { issuer } from "@openauthjs/openauth"
```

OpenAuth 构建在 [Hono](https://github.com/honojs/hono) 之上，这是一个极简 Web 框架，可以在任何地方运行。`issuer` 函数会创建一个 Hono 应用，其中实现了整个认证服务器，然后你可以将其部署到 AWS Lambda、Cloudflare Workers，或运行在 Node.js 或 Bun 下的容器中。

`issuer` 函数需要几样东西：

```ts
const app = issuer({
  providers: { ... },
  storage,
  subjects,
  success: async (ctx, value) => { ... }
})
```

首先我们需要定义一些启用的提供程序——这些要么是 Google、GitHub 等第三方身份提供商，要么是电子邮件/密码或 PIN 码等内置流程。你也可以实现自己的。我们来试试 GitHub 提供程序。

```ts
import { GithubProvider } from "@openauthjs/openauth/provider/github"

const app = issuer({
  providers: {
    github: GithubProvider({
      clientID: process.env.GITHUB_CLIENT_ID!,
      clientSecret: process.env.GITHUB_CLIENT_SECRET!,
      scopes: ["user:email"],
    }),
  },
  ...
})
```

提供程序需要一些配置——因为这是第三方身份提供商，所以没有 UI 需要担心，它只需要客户端 ID、密钥和一些作用域。我们来添加密码提供程序，它稍微复杂一点。

```ts
import { PasswordProvider } from "@openauthjs/openauth/provider/password"

const app = issuer({
  providers: {
    github: ...,
    password: PasswordProvider(...),
  },
  ...
})
```

密码提供程序相当复杂，因为用户名/密码涉及很多流程，所以有很多回调要实现。不过你可以选择使用默认 UI，它已经为你实现了所有这些。你唯一需要指定的是如何发送忘记密码/邮箱验证的验证码。这里我们会把验证码打印到日志，但你应该通过电子邮件发送。

```ts
import { PasswordProvider } from "@openauthjs/openauth/provider/password"
import { PasswordUI } from "@openauthjs/openauth/ui/password"

const app = issuer({
  providers: {
    github: ...,
    password: PasswordProvider(
      PasswordUI({
        sendCode: async (email, code) => {
          console.log(email, code)
        },
      }),
    ),
  },
  ...
})
```

接下来是 `subjects` 字段。Subjects 是认证流程结束时生成的访问令牌将映射到的对象。底层上，访问令牌是一个包含这些数据的 JWT。一开始你可能只需要一个 subject，但你可以为不同类型的用户定义更多。

```ts
import { object, string } from "valibot"

const subjects = createSubjects({
  user: object({
    userID: string(),
    // 如果是多租户应用，可能想在这里添加 workspaceID
    workspaceID: string(),
  }),
})
```

注意我们使用 [valibot](https://github.com/fabian-hiller/valibot) 来定义 subject 的形状，以便它能被正确验证。你可以使用任何遵循 [standard-schema 规范](https://github.com/standard-schema/standard-schema) 的验证库——下一版 Zod 将支持它。

通常你会想把 subjects 放在单独的文件中，因为它可以被你所有的应用导入。你可以在 `subjects` 字段中把它传给 issuer。

```ts
import { subjects } from "./subjects.js"

const app = issuer({
  providers: { ... },
  subjects,
  ...
})
```

接下来我们实现 `success` 回调，它在用户成功完成某个提供程序流程时接收 payload。

```ts
const app = issuer({
  providers: { ... },
  subjects,
  async success(ctx, value) {
    let userID
    if (value.provider === "password") {
      console.log(value.email)
      userID = ... // 查找用户或创建用户
    }
    if (value.provider === "github") {
      console.log(value.tokenset.access)
      userID = ... // 查找用户或创建用户
    }
    return ctx.subject("user", {
      userID,
      'a workspace id'
    })
  }
})
```

注意所有这些都是类型安全的——根据配置的提供程序，你会在 `value` 对象中收到不同的属性。另外，`subject` 方法只接受属性。注意——OpenAuth 中的大多数回调都可以返回一个 `Response` 对象。在这种情况下，如果出了什么问题，你可以返回 `Response.redirect("...")` 把他们送到别处，或渲染一个错误。

接下来是 `storage` 字段，它定义刷新令牌和密码哈希等内容存储在哪里。如果在 AWS 上，我们推荐 DynamoDB；如果在 Cloudflare 上，我们推荐 Cloudflare KV。我们也有用于测试的 MemoryStore。

```ts
import { MemoryStorage } from "@openauthjs/openauth/storage/memory"

const app = issuer({
  providers: { ... },
  subjects,
  async success(ctx, value) { ... },
  storage: MemoryStorage(),
})
```

现在我们可以部署了！以下是根据你的基础设施如何部署。

```ts
// Bun
export default app

// Cloudflare
export default app

// Lambda
import { handle } from "hono/aws-lambda"
export const handler = handle(app)

// Node.js
import { serve } from "@hono/node-server"
serve(app)
```

你现在有了一个集中式认证服务器。访问 `/.well-known/oauth-authorization-server` 测试一下——你可以看一个在线示例[这里](https://auth.terminal.shop/.well-known/oauth-authorization-server)。

### 认证客户端

由于这是一个标准 OAuth 服务器，你可以使用任何 OAuth 库，它都能工作。OpenAuth 确实为此提供了一些轻量工具，不过即使手动流程也很简单。你可以像这样创建一个客户端：

```ts
import { createClient } from "@openauthjs/openauth/client"

const client = createClient({
  clientID: "my-client",
  issuer: "https://auth.myserver.com", // OpenAuth 服务器的 URL
})
```

#### SSR 网站

如果你的前端有服务器组件，你可以使用代码流程。把用户重定向到这里：

```ts
const { url } = await client.authorize(
  <redirect-uri>,
  "code"
)
```

你可以编一个代表你的应用的 `client_id`。这会启动认证流程，用户将被重定向到你提供的 `redirect_uri`，并带有一个查询参数 `code`，你可以用它换取访问令牌。

```ts
// redirect_uri 是你最初传入的 redirect_uri，用于验证
const tokens = await client.exchange(query.get("code"), redirect_uri)
console.log(tokens.access, tokens.refresh)
```

你可能想把访问令牌和刷新令牌都存储在 HTTP-only cookie 中，这样它们会随以后的请求发送。然后你可以使用 `client` 来验证令牌。

```ts
const verified = await client.verify(subjects, cookies.get("access_token")!, {
  refresh: cookies.get("refresh_token") || undefined,
})
console.log(
  verified.subject.type,
  verified.subject.properties,
  verified.refresh,
  verified.access,
)
```

传入刷新令牌是可选的，但如果你传了，这个函数会在访问令牌过期时自动刷新它。它会返回新的访问令牌和刷新令牌，你应该把它们重新设置到 cookie 中。

#### SPA 网站、移动应用等

在没有服务器的情况下，你可以在前端使用带 `pkce` 的 `token` 流程。

```ts
const { challenge, url } = await client.authorize(<redirect_uri>, "code", { pkce: true })
localStorage.setItem("challenge", JSON.stringify(challenge))
location.href = url
```

当认证流程完成后，用户的浏览器将被重定向到 `redirect_uri`，并带有一个 `code` 查询参数。然后你可以用这个 code 换取访问/刷新令牌。

```ts
const challenge = JSON.parse(localStorage.getItem("challenge"))
const exchanged = await client.exchange(
  query.get("code"),
  redirect_uri,
  challenge.verifier,
)
if (exchanged.err) throw new Error("Invalid code")
localStorage.setItem("access_token", exchanged.tokens.access)
localStorage.setItem("refresh_token", exchanged.tokens.refresh)
```

然后当你向 API 发起请求时，可以在 `Authorization` 头中包含访问令牌。

```ts
const accessToken = localStorage.getItem("access_token")
fetch("https://auth.example.com/api/user", {
  headers: {
    Authorization: `Bearer ${accessToken}`,
  },
})
```

然后你可以在服务器上验证访问令牌。

```ts
const verified = await client.verify(subjects, accessToken)
console.log(verified.subject)
```

---

OpenAuth 由 [SST](https://sst.dev) 的维护者创建。

**加入我们的社区** [Discord](https://sst.dev/discord) | [YouTube](https://www.youtube.com/c/sst-dev) | [X.com](https://x.com/SST_dev)
