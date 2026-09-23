# `ic-auth-worker`

A Cloudflare Worker that forwards requests to [`ic_auth_verify_server`](../../rs/ic_auth_verify_server/README.md) running in Cloudflare Containers. The Rust service performs signature and delegation verification; the Worker selects a container instance and forwards the original request and response.

This deployable application is open source under the MIT license. `private: true` in `package.json` prevents accidental npm publication; install it from this repository. Its version is independent of the Rust crates.

## What is included

- `AuthContainer`: exposes port 8080, checks readiness at `GET /`, sleeps after 30 minutes of inactivity, and disables outbound container internet access.
- Regional routing: nine named regions plus a shared `default`, so arbitrary caller input cannot create arbitrary instance names.
- Transparent forwarding: JSON/CBOR bodies, headers, paths, and verifier status codes are preserved.
- Availability errors: a rejected `containerFetch` produces JSON `503`, with `Retry-After: 1`. The Containers SDK can also resolve with a `503` (no capacity), `429` (startup rate limit), or `500` (startup/proxy failure); those responses are preserved, including any retry header. A verifier's `401` remains a credential rejection.
- A shared root pnpm workspace and lockfile, generated Workers types, routing/forwarding tests, and CI checks.

## Prerequisites

Use Node.js 24+ and the pnpm version pinned in `package.json`. Docker must be installed and running for local container development and image builds. Deployment requires a Cloudflare account with Containers enabled and Wrangler authentication. See [Cloudflare's setup guide](https://developers.cloudflare.com/containers/get-started/) for account requirements.

Clone the whole repository: the image build uses the Rust workspace, not only this directory.

```bash
cd ts/ic-auth-worker
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm build
```

`typecheck` runs `wrangler types` before TypeScript checking. The generated `worker-configuration.d.ts` is ignored by Git and should be regenerated after Wrangler configuration changes. `build` bundles the Worker into `dist` using a dry run with container rollout disabled; it does not build a container or deploy anything.

## Local development

With Docker running:

```bash
pnpm dev
```

Wrangler builds the image and runs the Worker and its container locally. After startup:

```bash
curl --fail http://localhost:8787/
```

`POST /verify` accepts the same JSON/CBOR payloads as the [Rust HTTP service](../../rs/ic_auth_verify_server/README.md#post-verify). For example, replace the service URL in that README's TypeScript example with `http://localhost:8787/verify`.

Build just the container from this checkout with:

```bash
pnpm build:container
```

The image targets `linux/amd64`, including when building on an ARM host. Both standalone and Wrangler builds reuse `../../rs/ic_auth_verify_server/Dockerfile`. `image_build_context: "../.."` supplies the repository root, so its `COPY Cargo.toml Cargo.lock` and `COPY rs` instructions work. The root `.dockerignore` limits the context to Rust workspace inputs.

## Deployment

[wrangler.jsonc](wrangler.jsonc) builds the verifier from the current checkout. It contains no account ID, private registry address, or production route. Wrangler builds and uploads the image to the deploying account as part of deployment; see [Cloudflare image management](https://developers.cloudflare.com/containers/guides/image-management/).

```bash
pnpm exec wrangler login
pnpm deploy
```

Before deploying into your account, review the Worker name, container name, instance type, `max_instances`, and idle timeout for your workload. The default `workers_dev: false` and `preview_urls: false` configuration exposes the Worker through service bindings, without a public development URL. Configure a custom route or explicitly enable `workers_dev` if you want a public endpoint.

The container uses the Rust verifier's built-in mainnet root key and verification limits. It does not need an outbound network connection or secrets. See the [Wrangler container configuration reference](https://developers.cloudflare.com/workers/wrangler/configuration/#containers) for alternate image sources and deployment settings.

### Bind from another Worker

Add a service binding in the caller's Wrangler configuration. The `service` must match this Worker's deployed name:

```jsonc
{
	"services": [{ "binding": "IC_AUTH", "service": "ic-auth-worker" }]
}
```

The following helper submits an envelope to the verifier. Its `expectedDigest` should be computed by the caller from the request or challenge it expects, rather than trusted from client input.

```typescript
async function verifyEnvelope(
	incoming: Request,
	env: { IC_AUTH: Fetcher },
	signedEnvelope: string,
	expectedDigest: string
): Promise<Response> {
	const headers = new Headers({ 'Content-Type': 'application/json' })
	const colo = incoming.cf?.colo
	if (typeof colo === 'string') headers.set('x-edge-name', colo)

	return env.IC_AUTH.fetch('https://ic-auth.internal/verify', {
		method: 'POST',
		headers,
		body: JSON.stringify({
			signed_envelope: signedEnvelope,
			expect_digest: expectedDigest
		})
	})
}
```

The hostname in this example is only a Request URL passed through the service binding; it does not require a DNS record. Both fields are Base64URL strings: `signed_envelope` wraps CBOR envelope bytes and `expect_digest` contains exactly 32 bytes. Add `expect_target` when target membership must be checked.

## Routing

[src/region.ts](src/region.ts) maps requests to the fixed names `wnam`, `enam`, `sam`, `weur`, `eeur`, `apac`, `oc`, `afr`, `me`, and `default`.

1. A nonempty `x-edge-name` takes precedence; callers should populate it with their incoming `request.cf.colo`, such as `SJC` or `FRA`.
2. Without that header, the router looks up `request.cf.colo`.
3. An unknown colo falls back to `request.cf.continent` when available, then to `default`. An unknown nonempty header does not retry the `cf.colo` lookup.

Colo and continent matching is case-insensitive. Country codes, city names, and arbitrary strings cannot become instance names. The header is a routing hint, not an authentication or authorization signal. Set it from the caller's trusted request metadata rather than forwarding an incoming header blindly.

Each regional name passes a matching Durable Object `locationHint`; the default has no hint. Hints are best effort, apply only on initial creation, and do not guarantee placement or move existing objects. See [Cloudflare's data-location documentation](https://developers.cloudflare.com/durable-objects/reference/data-location/#provide-a-location-hint).

The copied colo table is a routing snapshot. Its splits at 104°W for North America and 19°E for Europe are application heuristics. Review it when adding colos; unknown entries already fall back safely. Source data is available from [Cloudflare's location list](https://speed.cloudflare.com/locations).

The configuration permits 10 concurrently active containers for a roster of ten names. It is a ceiling, not a reservation. The 30-minute idle timeout favors warm verification instances; adjust it together with capacity for your traffic.

The Worker logs the instance name, status and elapsed time for `429`/`5xx` responses and rejected container calls, without reading request or response bodies. Use `wrangler tail` during diagnosis, or enable Workers observability in your deployment to retain logs; it is disabled by default. Callers can retry a verification request a bounded number of times for transient `429`/`5xx` failures, honoring `Retry-After` when present and using backoff when it is absent. Do not retry credential rejections (`401`) unchanged. The Worker itself does not retry requests.

## Migration from the original project

This package was migrated from the former `fuxi/src/ic-auth-worker` application. The Worker name `ic-auth-worker`, Durable Object class `AuthContainer`, binding `AUTH_CONTAINER`, migration tag `v1`, container name, and regional instance names are preserved. Existing service-binding callers can retain the same API and `x-edge-name` convention.

The original account-specific image reference is replaced by the in-repository Dockerfile. Existing deployments should retain their account, names, and complete Durable Object migration history when adopting this checkout; changing the repository does not itself deploy or move cloud resources. This migration does not change the original project's deployment.

## Checks

```bash
pnpm format:check
pnpm typecheck
pnpm test
pnpm build
```

Tests run in Node with the Workers-only Container base class mocked. They cover regional selection, a bounded roster, request/response preservation, binary CBOR, verifier error statuses, and retryable container failures. They do not exercise a real container runtime; use `pnpm dev` for that check. CI runs the same checks without Cloudflare credentials or deployment.

## License

Copyright © 2024-2026 [LDC Labs](https://github.com/ldclabs).

Licensed under the MIT License. See [LICENSE](LICENSE).
