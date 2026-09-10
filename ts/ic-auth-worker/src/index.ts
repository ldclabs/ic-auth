import { Container } from '@cloudflare/containers'
import { instanceFor } from './region.js'

/** Runs rs/ic_auth_verify_server using the Dockerfile in wrangler.jsonc. */
export class AuthContainer extends Container<Env> {
	defaultPort = 8080
	envVars = { SOCKET_ADDR: '0.0.0.0:8080' }
	// The verifier serves GET /, not the library's default /ping endpoint.
	pingEndpoint = 'localhost/'
	// Keep instances warm across short traffic gaps; tune for your workload.
	sleepAfter = '30m'
	// Verification uses local cryptography and the compiled-in IC root key.
	enableInternet = false
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const { name, locationHint } = instanceFor(request)
		const ns = env.AUTH_CONTAINER
		// Pass the hint on first creation; later calls do not move the instance.
		const container = ns.get(
			ns.idFromName(name),
			locationHint ? { locationHint } : undefined
		)
		try {
			return await container.containerFetch(request)
		} catch (err) {
			// Keep infrastructure failures distinct from rejected credentials (401).
			console.error(`containerFetch failed on instance ${name}`, err)
			return Response.json(
				{ error: 'ic-auth verifier unavailable' },
				{ status: 503, headers: { 'retry-after': '1' } }
			)
		}
	}
}
