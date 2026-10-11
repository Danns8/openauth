import type { Env } from "./worker.js"
import type { Provider } from "../packages/openauth/src/provider/provider.js"
import type { RegisteredClients } from "../packages/openauth/src/security.js"

// Configure providers, registered clients, and user mapping here, then push to master.
// Supply provider secrets through Cloudflare Worker secrets; never commit them.
export function authConfig(_env: Env) {
  return {
    providers: {} as Record<string, Provider<any>>,
    clients: {} as RegisteredClients,
    async success(): Promise<Response> {
      // Replace with ctx.subject("user", { id: yourStableUserID }).
      // Each authenticated identity must map to its own stable user ID.
      return new Response("Authentication is not configured", { status: 503 })
    },
  }
}
