import type { ExecutionContext, KVNamespace, DurableObjectNamespace } from "@cloudflare/workers-types"
import { issuer } from "../packages/openauth/src/issuer.js"
import { createSubjects } from "../packages/openauth/src/subject.js"
import { CloudflareStorage } from "../packages/openauth/src/storage/cloudflare.js"
import { DurableObjectSecurityStorage } from "../packages/openauth/src/storage/security-cloudflare.js"
import { object, string } from "valibot"
import { authConfig } from "./auth.config.js"

export { OpenAuthSecurity } from "../packages/openauth/src/storage/security-cloudflare.js"

export interface Env {
  AUTH_KV: KVNamespace
  AUTH_SECURITY: DurableObjectNamespace
  ISSUER_URL?: string
}

export const subjects = createSubjects({ user: object({ id: string() }) })

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const config = authConfig(env)
    const url = new URL(request.url)
    if ((request.method === "GET" || request.method === "HEAD") &&
        (url.pathname === "/" || url.pathname === "/health")) {
      return Response.json({
        service: "OpenAuth",
        status: "deployed",
        authenticationConfigured: Object.keys(config.providers).length > 0 && Object.keys(config.clients).length > 0,
        discovery: "/.well-known/oauth-authorization-server",
      }, { headers: { "Cache-Control": "no-store" } })
    }
    return issuer({
      storage: CloudflareStorage({ namespace: env.AUTH_KV }),
      security: DurableObjectSecurityStorage({ namespace: env.AUTH_SECURITY, name: "openauth" }),
      issuer: env.ISSUER_URL,
      subjects,
      ...config,
    }).fetch(request, env, ctx)
  },
}
