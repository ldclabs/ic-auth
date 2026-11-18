//! HTTP verification service for IC-Auth signed envelopes.
//!
//! The server exposes a small JSON/CBOR API:
//!
//! - `GET /` returns service name and version.
//! - `POST /verify` verifies a CBOR-encoded [`SignedEnvelope`] embedded in a
//!   JSON or CBOR request body and returns the authenticated principal.
//!
//! Set `SOCKET_ADDR` to change the listen address. The default is
//! `127.0.0.1:8080`.

#[cfg(not(test))]
use axum::BoxError;
use axum::{
    Router,
    extract::{DefaultBodyLimit, State},
    http::{self, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing,
};
use candid::Principal;
use ic_auth_types::{ByteArrayB64, ByteBufB64, DelegationPermissions, cbor_from_slice};
use ic_auth_verifier::{MAX_CERT_TIME_OFFSET_NS, SignedEnvelope};
use serde::{Deserialize, Serialize};
#[cfg(not(test))]
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use structured_logger::unix_ms;
#[cfg(not(test))]
use structured_logger::{Builder, async_json::new_writer, get_env_level};
#[cfg(not(test))]
use tokio::signal;
use tokio::sync::Semaphore;

mod content;
use content::{Content, Format, text_response};

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Largest accepted request body. A signed envelope is a few kilobytes even
/// with a full delegation chain, so this leaves ample headroom while keeping a
/// client from making the server buffer megabytes per request.
const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Clone, Deserialize, Serialize)]
struct VerifyInput {
    /// Deterministic-CBOR encoded `SignedEnvelope`.
    signed_envelope: ByteBufB64,
    /// Optional canister target that every targeted delegation must authorize.
    expect_target: Option<Principal>,
    /// Optional expected content digest. When omitted, the digest embedded in
    /// the signed envelope is used.
    expect_digest: Option<ByteArrayB64<32>>,
}

#[derive(Clone, Deserialize, Serialize)]
struct VerifyOutput {
    /// Principal derived from the verified envelope public key.
    user: Principal,
    /// Request types permitted by every link in the verified delegation chain.
    permissions: DelegationPermissions,
}

#[derive(Clone, Serialize)]
struct InfoOutput<'a> {
    /// Package name.
    name: &'a str,
    /// Package version.
    version: &'a str,
}

// cargo run -p ic_auth_verify_server
#[cfg(not(test))]
#[tokio::main]
async fn main() -> Result<(), BoxError> {
    // Initialize structured logging with Json format
    Builder::with_level(&get_env_level().to_string())
        .with_target_writer("*", new_writer(tokio::io::stdout()))
        .init();

    let addr_str = std::env::var("SOCKET_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let addr: SocketAddr = addr_str.parse()?;
    let certificate_time_offset_ns = match std::env::var("MAX_CERT_TIME_OFFSET_SECS") {
        Ok(value) => {
            let seconds: u64 = value
                .parse()
                .map_err(|err| format!("invalid MAX_CERT_TIME_OFFSET_SECS: {err}"))?;
            std::time::Duration::from_secs(seconds).as_nanos()
        }
        Err(std::env::VarError::NotPresent) => MAX_CERT_TIME_OFFSET_NS,
        Err(err) => return Err(format!("invalid MAX_CERT_TIME_OFFSET_SECS: {err}").into()),
    };
    let listener = tokio::net::TcpListener::bind(addr).await?;
    log::warn!(
        "{}@{} listening on {}",
        APP_NAME,
        APP_VERSION,
        listener.local_addr()?
    );

    axum::serve(listener, app(certificate_time_offset_ns))
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn app(certificate_time_offset_ns: u128) -> Router {
    Router::new()
        .route("/", routing::get(get_information))
        .route("/verify", routing::post(post_verify))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(certificate_time_offset_ns)
}

#[cfg(not(test))]
pub async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    log::warn!("received termination signal, starting graceful shutdown");
}

async fn get_information(headers: HeaderMap) -> impl IntoResponse {
    let info = InfoOutput {
        name: APP_NAME,
        version: APP_VERSION,
    };
    let response = match Format::for_response(&headers) {
        Some(format) => Content(format, info).into_response(),
        None => text_response(
            StatusCode::NOT_ACCEPTABLE,
            "supported content types: application/json, application/cbor".into(),
        ),
    };
    ([(http::header::VARY, "Accept, Content-Type")], response)
}

// Limit CPU work independently of Tokio's blocking-thread pool size.
static VERIFY_SLOTS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| {
    Arc::new(Semaphore::new(
        std::thread::available_parallelism().map_or(1, |n| n.get()),
    ))
});

type VerifyError = (StatusCode, String);

/// POST /verify
async fn post_verify(
    State(certificate_time_offset_ns): State<u128>,
    Content(format, req): Content<VerifyInput>,
) -> Response {
    match verify_with_limit(req, Arc::clone(&VERIFY_SLOTS), certificate_time_offset_ns).await {
        Ok(out) => Content(format, out).into_response(),
        Err((status, err)) => text_response(status, err),
    }
}

async fn verify_with_limit(
    req: VerifyInput,
    slots: Arc<Semaphore>,
    certificate_time_offset_ns: u128,
) -> Result<VerifyOutput, VerifyError> {
    let permit = slots.acquire_owned().await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "verification unavailable".to_string(),
        )
    })?;
    tokio::task::spawn_blocking(move || {
        // Keep the permit until CPU work finishes, even if the HTTP caller
        // disconnects and drops its waiting future.
        let _permit = permit;
        verify_request(req, certificate_time_offset_ns)
    })
    .await
    .map_err(|err| {
        log::error!("verification task failed: {err}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "verification task failed".to_string(),
        )
    })?
}

fn verify_request(
    req: VerifyInput,
    certificate_time_offset_ns: u128,
) -> Result<VerifyOutput, VerifyError> {
    let signed_envelope: SignedEnvelope =
        cbor_from_slice(req.signed_envelope.as_slice()).map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                format!("failed to decode signed_envelope CBOR: {err}"),
            )
        })?;
    // Read time when verification starts, after any wait for a CPU slot.
    let permissions = signed_envelope
        .verify_with_certificate_time_offset(
            unix_ms(),
            req.expect_target,
            req.expect_digest.as_ref().map(|d| d.as_slice()),
            certificate_time_offset_ns,
        )
        .map_err(|err| (StatusCode::UNAUTHORIZED, err))?;
    Ok(VerifyOutput {
        user: signed_envelope.sender(),
        permissions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Bytes, to_bytes};
    use ic_auth_verifier::{BasicIdentity, Identity};

    async fn response_parts(response: axum::response::Response) -> (StatusCode, HeaderMap, Bytes) {
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, headers, body)
    }

    fn signed_verify_input() -> (VerifyInput, Principal) {
        input_for(&BasicIdentity::from_raw_key(&[8u8; 32]))
    }

    fn input_for(identity: &impl Identity) -> (VerifyInput, Principal) {
        let envelope = SignedEnvelope::sign_message(identity, b"hello world").unwrap();
        let user = identity.sender().unwrap();
        (
            VerifyInput {
                signed_envelope: envelope.to_bytes().into(),
                expect_target: None,
                expect_digest: None,
            },
            user,
        )
    }

    #[tokio::test]
    async fn get_information_returns_requested_format() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::ACCEPT, "application/json".parse().unwrap());
        let (status, response_headers, body) =
            response_parts(get_information(headers).await.into_response()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            response_headers[http::header::CONTENT_TYPE],
            "application/json"
        );
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["name"], APP_NAME);
        assert_eq!(value["version"], APP_VERSION);

        let mut headers = HeaderMap::new();
        headers.insert(http::header::ACCEPT, "application/cbor".parse().unwrap());
        let (status, response_headers, body) =
            response_parts(get_information(headers).await.into_response()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            response_headers[http::header::CONTENT_TYPE],
            "application/cbor"
        );
        let value: std::collections::BTreeMap<String, String> =
            cbor_from_slice(body.as_ref()).unwrap();
        assert_eq!(value["name"], APP_NAME);
        assert_eq!(value["version"], APP_VERSION);

        // curl sends `Accept: */*` and browsers send a `*/*;q=...` tail; both
        // used to get `406` from the documented info endpoint.
        for accept in ["*/*", "text/html,application/xhtml+xml,*/*;q=0.8"] {
            let mut headers = HeaderMap::new();
            headers.insert(http::header::ACCEPT, accept.parse().unwrap());
            let (status, response_headers, body) =
                response_parts(get_information(headers).await.into_response()).await;
            assert_eq!(status, StatusCode::OK, "Accept: {accept}");
            assert_eq!(
                response_headers[http::header::CONTENT_TYPE],
                "application/json"
            );
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value["name"], APP_NAME);
        }

        // A request with no `Accept` accepts anything, so it gets JSON too.
        let (status, response_headers, _) =
            response_parts(get_information(HeaderMap::new()).await.into_response()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            response_headers[http::header::CONTENT_TYPE],
            "application/json"
        );

        // Only an `Accept` that names nothing supported is still a 406.
        let mut headers = HeaderMap::new();
        headers.insert(http::header::ACCEPT, "application/xml".parse().unwrap());
        let (status, _, body) =
            response_parts(get_information(headers).await.into_response()).await;
        assert_eq!(status, StatusCode::NOT_ACCEPTABLE);
        assert_eq!(
            body,
            Bytes::from_static(b"supported content types: application/json, application/cbor")
        );
    }

    #[tokio::test]
    async fn post_verify_accepts_valid_json_and_cbor() {
        let (input, user) = signed_verify_input();

        let (status, headers, body) = response_parts(
            post_verify(
                State(MAX_CERT_TIME_OFFSET_NS),
                Content(Format::Json, input.clone()),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[http::header::CONTENT_TYPE], "application/json");
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["user"], user.to_text());
        assert_eq!(value["permissions"], "all");

        let (status, headers, body) = response_parts(
            post_verify(State(MAX_CERT_TIME_OFFSET_NS), Content(Format::Cbor, input))
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[http::header::CONTENT_TYPE], "application/cbor");
        let value: VerifyOutput = cbor_from_slice(body.as_ref()).unwrap();
        assert_eq!(value.user, user);
        assert_eq!(value.permissions, DelegationPermissions::All);
    }

    #[tokio::test]
    async fn post_verify_returns_the_permissions_shared_by_all_links() {
        use ic_agent::identity::{
            DelegatedIdentity, Delegation, DelegationPermissions as Permissions, SignedDelegation,
        };
        use tower::ServiceExt;

        for (first, second, expected) in [
            (
                Some(Permissions::Queries),
                Some(Permissions::All),
                "queries",
            ),
            (None, Some(Permissions::Queries), "queries"),
            (Some(Permissions::All), None, "all"),
        ] {
            let root = BasicIdentity::from_raw_key(&[1; 32]);
            let middle = BasicIdentity::from_raw_key(&[2; 32]);
            let session = BasicIdentity::from_raw_key(&[3; 32]);
            let chain = [(&root, &middle, first), (&middle, &session, second)]
                .into_iter()
                .map(|(from, to, permissions)| {
                    let delegation = Delegation {
                        pubkey: to.public_key().unwrap(),
                        expiration: u64::MAX,
                        targets: None,
                        permissions,
                    };
                    let signature = from
                        .sign_delegation(&delegation)
                        .unwrap()
                        .signature
                        .unwrap();
                    SignedDelegation {
                        delegation,
                        signature,
                    }
                })
                .collect();
            let delegated = DelegatedIdentity::new_unchecked(
                root.public_key().unwrap(),
                Box::new(session),
                chain,
            );
            let (input, user) = input_for(&delegated);
            let response = app(MAX_CERT_TIME_OFFSET_NS)
                .oneshot(
                    http::Request::post("/verify")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(axum::body::Body::from(serde_json::to_vec(&input).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let (status, _, body) = response_parts(response).await;
            assert_eq!(status, StatusCode::OK);
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value["permissions"], expected);
            assert_eq!(value["user"], user.to_text());
        }
    }

    #[tokio::test]
    async fn post_verify_rejects_bad_and_unauthorized_inputs() {
        let bad_cbor = VerifyInput {
            signed_envelope: vec![0xff].into(),
            expect_target: None,
            expect_digest: None,
        };
        let (status, _, body) = response_parts(
            post_verify(
                State(MAX_CERT_TIME_OFFSET_NS),
                Content(Format::Json, bad_cbor),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            std::str::from_utf8(&body)
                .unwrap()
                .contains("failed to decode signed_envelope CBOR")
        );

        let (mut input, _) = signed_verify_input();
        input.expect_digest = Some([0; 32].into());
        let (status, _, body) = response_parts(
            post_verify(State(MAX_CERT_TIME_OFFSET_NS), Content(Format::Json, input))
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            std::str::from_utf8(&body)
                .unwrap()
                .contains("Content digest does not match")
        );
    }

    #[tokio::test]
    async fn app_routes_requests_and_limits_body_size() {
        use tower::ServiceExt;

        let post = |body: Vec<u8>| {
            http::Request::post("/verify")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body))
                .unwrap()
        };

        let (input, user) = signed_verify_input();
        let response = app(MAX_CERT_TIME_OFFSET_NS)
            .oneshot(post(serde_json::to_vec(&input).unwrap()))
            .await
            .unwrap();
        let (status, _, body) = response_parts(response).await;
        assert_eq!(status, StatusCode::OK);
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["user"], user.to_text());
        assert_eq!(value["permissions"], "all");

        // Whitespace is valid JSON padding, so only the size limit can reject
        // this body.
        let response = app(MAX_CERT_TIME_OFFSET_NS)
            .oneshot(post(vec![b' '; MAX_BODY_BYTES + 1]))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let response = app(MAX_CERT_TIME_OFFSET_NS)
            .oneshot(
                http::Request::get("/")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_information_negotiates_only_supported_acceptable_formats() {
        for (accept, status, content_type) in [
            (
                "application/json;q=0, application/cbor;q=0, */*;q=1",
                StatusCode::NOT_ACCEPTABLE,
                "text/plain",
            ),
            (
                "text/plain;q=1, application/json;q=0.5",
                StatusCode::OK,
                "application/json",
            ),
            (
                "application/json;q=0, */*;q=0.5",
                StatusCode::OK,
                "application/cbor",
            ),
            (
                "application/cbor;q=0, */*;q=0.5",
                StatusCode::OK,
                "application/json",
            ),
            (
                "application/json;q=2, application/cbor;q=0.5",
                StatusCode::OK,
                "application/cbor",
            ),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(http::header::ACCEPT, accept.parse().unwrap());
            let response = get_information(headers).await.into_response();
            assert_eq!(response.status(), status, "{accept}");
            assert_eq!(
                response.headers()[http::header::VARY],
                "Accept, Content-Type"
            );
            assert_eq!(
                response.headers()[http::header::CONTENT_TYPE],
                content_type,
                "{accept}"
            );
        }
        let mut headers = HeaderMap::new();
        headers.append(http::header::ACCEPT, "application/xml".parse().unwrap());
        headers.append(http::header::ACCEPT, "application/json".parse().unwrap());
        assert_eq!(
            get_information(headers).await.into_response().status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn verification_waits_for_a_slot_without_blocking_the_runtime() {
        use std::time::Duration;
        let slots = Arc::new(Semaphore::new(1));
        let held = slots.clone().acquire_owned().await.unwrap();
        let (input, user) = signed_verify_input();
        let mut pending = Box::pin(verify_with_limit(
            input,
            slots.clone(),
            MAX_CERT_TIME_OFFSET_NS,
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), pending.as_mut())
                .await
                .is_err()
        );
        assert_eq!(
            get_information(HeaderMap::new())
                .await
                .into_response()
                .status(),
            StatusCode::OK
        );
        drop(held);
        assert_eq!(pending.await.unwrap().user, user);
        assert_eq!(slots.available_permits(), 1);
        let bad = VerifyInput {
            signed_envelope: vec![0xff].into(),
            expect_target: None,
            expect_digest: None,
        };
        assert!(matches!(
            verify_with_limit(bad, slots.clone(), MAX_CERT_TIME_OFFSET_NS).await,
            Err((StatusCode::BAD_REQUEST, _))
        ));
        assert_eq!(slots.available_permits(), 1);
    }
}
