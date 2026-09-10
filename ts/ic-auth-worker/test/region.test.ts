import { describe, expect, it } from 'vitest'
import { EDGE_NAME_HEADER, instanceFor } from '../src/region.js'

const req = (init?: {
	cf?: Record<string, unknown>
	headers?: Record<string, string>
}): Request =>
	Object.assign(
		new Request('https://ic-auth.example/verify', {
			method: 'POST',
			headers: init?.headers
		}),
		{ cf: init?.cf }
	) as Request

describe('instanceFor', () => {
	it('pins a stated colo to the instance of its own region', () => {
		expect(
			instanceFor(req({ headers: { [EDGE_NAME_HEADER]: 'FRA' } }))
		).toEqual({ name: 'weur', locationHint: 'weur' })
		expect(
			instanceFor(req({ headers: { [EDGE_NAME_HEADER]: 'SJC' } }))
		).toEqual({ name: 'wnam', locationHint: 'wnam' })
		expect(
			instanceFor(req({ headers: { [EDGE_NAME_HEADER]: 'iad' } }))
		).toEqual({ name: 'enam', locationHint: 'enam' })
		expect(
			instanceFor(req({ headers: { [EDGE_NAME_HEADER]: 'DXB' } }))
		).toEqual({ name: 'me', locationHint: 'me' })
	})

	it('reads cf.colo when the request arrived at an edge instead of over a binding', () => {
		expect(instanceFor(req({ cf: { colo: 'SIN' } }))).toEqual({
			name: 'apac',
			locationHint: 'apac'
		})
	})

	it('lets the caller-stated colo win over cf — a service binding carries no cf at all', () => {
		expect(
			instanceFor(
				req({ cf: { colo: 'FRA' }, headers: { [EDGE_NAME_HEADER]: 'SYD' } })
			)
		).toEqual({ name: 'oc', locationHint: 'oc' })
	})

	it('falls back to the continent for a colo the table has not heard of', () => {
		expect(instanceFor(req({ cf: { colo: 'ZZZ', continent: 'SA' } }))).toEqual({
			name: 'sam',
			locationHint: 'sam'
		})
		// 'AN' is deliberately off the roster.
		expect(instanceFor(req({ cf: { colo: 'ZZZ', continent: 'AN' } }))).toEqual({
			name: 'default'
		})
	})

	it('shares one unpinned instance when nobody said where they are', () => {
		expect(instanceFor(req())).toEqual({ name: 'default' })
		// What a caller sends when it had no location to pass on.
		expect(
			instanceFor(req({ headers: { [EDGE_NAME_HEADER]: 'global' } }))
		).toEqual({ name: 'default' })
		// The city and country fallbacks of the callers' own edge-name helper.
		for (const value of ['San Jose', 'US', 'CN']) {
			expect(
				instanceFor(req({ headers: { [EDGE_NAME_HEADER]: value } }))
			).toEqual({ name: 'default' })
		}
	})

	it('keeps the roster closed — an unknown edge name can never mint its own instance', () => {
		for (const value of ['ZZZ', 'weur', 'default', '', 'a'.repeat(2000)]) {
			expect(
				instanceFor(req({ headers: { [EDGE_NAME_HEADER]: value } }))
			).toEqual({ name: 'default' })
		}
	})

	it('does not route inherited object members to a garbage instance', () => {
		// A plain-object lookup table answers `constructor` with a truthy
		// function, which would become an instance name.
		for (const value of ['constructor', '__proto__', 'toString']) {
			expect(
				instanceFor(req({ headers: { [EDGE_NAME_HEADER]: value } }))
			).toEqual({ name: 'default' })
			expect(instanceFor(req({ cf: { continent: value } }))).toEqual({
				name: 'default'
			})
		}
	})
})
