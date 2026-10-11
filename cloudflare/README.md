# Cloudflare Workers 部署

此 Worker 直接打包本仓库 `packages/openauth/src`，因此修改这个分支的 OpenAuth 源码会进入下一次部署，不依赖 npm 上游发布。

## 当前状态

- Worker 名称：`openauth`，使用默认 `workers.dev` 域名。
- 服务地址：<https://openauth.danns.workers.dev>。
- 普通记录：`AUTH_KV`。
- 安全事务、签名密钥、授权码及刷新令牌状态：SQLite Durable Object `AUTH_SECURITY`。
- 尚未配置登录提供商和客户端，授权请求默认被拒绝。
- `/` 和 `/health` 返回部署状态；OAuth 发现文档位于 `/.well-known/oauth-authorization-server`，公钥位于 `/.well-known/jwks.json`。

## 本地操作

```sh
bun install --frozen-lockfile
bun run worker:build
bun run worker:dev
bun run worker:deploy
```

首次部署需要 Cloudflare 授权；`wrangler.jsonc` 已绑定当前账号及创建的 KV。保留 Durable Object 名称和迁移历史，避免切换已有认证状态。

## GitHub 自动构建

当前 Worker 已连接 `Danns8/openauth` 的 `master` 分支，使用专用的 `openauth token`。提交推送会触发 Cloudflare Workers Builds。

在 Cloudflare 控制台选择 **Workers & Pages → openauth → Settings → Builds → Connect**，连接 GitHub 仓库 `Danns8/openauth`。

- 生产分支：`master`
- 根目录：仓库根目录 `/`
- 构建命令：`bun install --frozen-lockfile && bun run worker:build`
- 部署命令：`bun run worker:deploy`
- Bun 版本：`1.2.18`（构建环境变量 `BUN_VERSION`）
- 如需只部署生产分支，关闭非生产分支构建。

连接后，推送到 `master` 会触发构建和部署。控制台的构建日志和最新部署提交可用于确认自动更新成功。

## 后续手动配置认证

编辑 `cloudflare/auth.config.ts`，完成三个部分：

1. `providers`：从 `packages/openauth/src/provider` 导入要启用的提供商，按该提供商文档配置。将需要的密钥作为 Worker secrets 设置，并在 `Env` 添加相应类型。
2. `clients`：配置客户端 ID 与完整回调地址，例如 `{ "my-app": { redirectURIs: ["https://your-app.example/callback"] } }`。仅本地回调可以使用 `http://localhost`。
3. `success(ctx, value)`：按提供商的可信身份查找或创建用户，返回 `ctx.subject("user", { id: stableUserID })`。不要给不同用户返回同一个示例 ID。

第三方 OAuth 应用的回调地址为 `https://<worker域名>/<provider名称>/callback`。邮箱登录还需实现真实的验证码邮件发送。

在 Cloudflare **Settings → Variables and Secrets** 设置运行时配置；或执行 `bunx wrangler secret put SECRET_NAME`。不要把密钥放进代码、GitHub 仓库或构建日志。`keep_vars: true` 保留控制台设置的普通运行时变量，后续 Git 部署不会将其清空。

如需要固定公开 issuer，可设置普通运行时变量 `ISSUER_URL=https://<worker域名>`。
