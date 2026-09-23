import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// The Workers-only Container base class is exercised by Wrangler. Mock it here
// so these tests can check our forwarding contract without Docker or an account.
vi.mock('@cloudflare/containers', () => ({ Container: class {} }))

import worker from '../src/index.js'

function binding(response: Response) {
	const id = {} as DurableObjectId
	const containerFetch = vi.fn().mockResolvedValue(response)
	const ns = {
		idFromName: vi.fn().mockReturnValue(id),
		get: vi.fn().mockReturnValue({ containerFetch })
	}
	return {
		id,
		ns,
		containerFetch,
		env: { AUTH_CONTAINER: ns } as unknown as Env
	}
}

beforeEach(() => {
	vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => vi.restoreAllMocks())

describe('Worker forwarding', () => {
	it('forwards the original request and returns the verifier response unchanged', async () => {
		const upstream = Response.json({ user: 'verified-principal' })
		const { env, id, ns, containerFetch } = binding(upstream)
		const request = new Request('https://ic-auth.example/verify?trace=1', {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				'x-edge-name': 'FRA'
			},
			body: JSON.stringify({ signed_envelope: 'encoded-envelope' })
		})

		const response = await worker.fetch(request, env)

		expect(ns.idFromName).toHaveBeenCalledWith('weur')
		expect(ns.get).toHaveBeenCalledWith(id, { locationHint: 'weur' })
		expect(containerFetch).toHaveBeenCalledExactlyOnceWith(request)
		expect(response).toBe(upstream)
		expect(await request.json()).toEqual({
			signed_envelope: 'encoded-envelope'
		})
		expect(await response.json()).toEqual({ user: 'verified-principal' })
	})

	it('routes local or unlocated metadata requests to the shared default', async () => {
		const upstream = Response.json({
			name: 'ic_auth_verify_server',
			version: 'test'
		})
		const { env, id, ns } = binding(upstream)

		expect(
			await worker.fetch(new Request('https://ic-auth.example/'), env)
		).toBe(upstream)
		expect(ns.idFromName).toHaveBeenCalledWith('default')
		expect(ns.get).toHaveBeenCalledWith(id, undefined)
	})

	it('preserves binary CBOR bodies and content types', async () => {
		const bytes = new Uint8Array([0xa1, 0x61, 0x75, 0x41, 0x04])
		const upstream = new Response(bytes, {
			headers: { 'content-type': 'application/cbor' }
		})
		const { env, containerFetch } = binding(upstream)
		const request = new Request('https://ic-auth.example/verify', {
			method: 'POST',
			headers: { 'content-type': 'application/cbor' },
			body: bytes
		})

		const response = await worker.fetch(request, env)
		expect(containerFetch).toHaveBeenCalledExactlyOnceWith(request)
		expect(response.headers.get('content-type')).toBe('application/cbor')
		expect(new Uint8Array(await response.arrayBuffer())).toEqual(bytes)
		expect(new Uint8Array(await request.arrayBuffer())).toEqual(bytes)
	})

	it.each([400, 401, 404, 415, 429, 500, 502, 503, 504])(
		'preserves a verifier HTTP %i response',
		async (status) => {
			const upstream = new Response('upstream error', {
				status,
				headers: { 'content-type': 'text/plain' }
			})
			const { env } = binding(upstream)

			const response = await worker.fetch(
				new Request('https://ic-auth.example/verify'),
				env
			)
			expect(response).toBe(upstream)
			expect(response.status).toBe(status)
			expect(await response.text()).toBe('upstream error')
			if (status === 429 || status >= 500) {
				expect(console.warn).toHaveBeenCalledExactlyOnceWith(
					'ic-auth upstream failure',
					{
						instance: 'default',
						status,
						durationMs: expect.any(Number)
					}
				)
			} else {
				expect(console.warn).not.toHaveBeenCalled()
			}
		}
	)

	it.each([
		[503, 'There is no Container instance available at this time.'],
		[429, 'you are requesting too many containers per second'],
		[500, 'Failed to start container: startup timeout']
	] as const)(
		'preserves a resolved container failure (%i) and its retry guidance',
		async (status, body) => {
			const upstream = new Response(body, {
				status,
				headers: { 'retry-after': '3' }
			})
			const { env } = binding(upstream)
			const response = await worker.fetch(
				new Request('https://ic-auth.example/verify', {
					headers: { 'x-edge-name': 'FRA' }
				}),
				env
			)
			expect(response).toBe(upstream)
			expect(response.headers.get('retry-after')).toBe('3')
			expect(await response.text()).toBe(body)
			expect(console.warn).toHaveBeenCalledExactlyOnceWith(
				'ic-auth upstream failure',
				{
					instance: 'weur',
					status,
					durationMs: expect.any(Number)
				}
			)
		}
	)

	it('returns a retryable 503 when containerFetch rejects', async () => {
		const { env, containerFetch } = binding(new Response())
		containerFetch.mockRejectedValue(new Error('container unavailable'))
		vi.spyOn(console, 'error').mockImplementation(() => {})

		const response = await worker.fetch(
			new Request('https://ic-auth.example/verify'),
			env
		)

		expect(response.status).toBe(503)
		expect(response.headers.get('retry-after')).toBe('1')
		expect(await response.json()).toEqual({
			error: 'ic-auth verifier unavailable'
		})
		expect(console.error).toHaveBeenCalledExactlyOnceWith(
			'ic-auth containerFetch rejected',
			{
				instance: 'default',
				status: 503,
				durationMs: expect.any(Number),
				error: expect.any(Error)
			}
		)
	})
})
