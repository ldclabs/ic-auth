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

use axum::{BoxError, http::StatusCode, response::IntoResponse};
#[cfg(not(test))]
use axum::{Router, routing};
use candid::Principal;
use http::HeaderMap;
use ic_auth_types::{ByteArrayB64, ByteBufB64, cbor_from_slice};
use ic_auth_verifier::SignedEnvelope;
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    sync::{Arc, LazyLock},
};
use structured_logger::unix_ms;
#[cfg(not(test))]
use structured_logger::{Builder, async_json::new_writer, get_env_level};
#[cfg(not(test))]
use tokio::signal;
use tokio::sync::Semaphore;

mod content;
use content::Content;

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

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

    let signal = shutdown_signal();
    let app = Router::new()
        .route("/", routing::get(get_information))
        .route("/verify", routing::post(post_verify));

    let addr_str = std::env::var("SOCKET_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let addr: SocketAddr = addr_str.parse()?;
    let listener = create_reuse_port_listener(addr).await?;
    log::warn!("{}@{} listening on {:?}", APP_NAME, APP_VERSION, addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(signal)
        .await?;

    Ok(())
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

pub async fn create_reuse_port_listener(
    addr: SocketAddr,
) -> Result<tokio::net::TcpListener, BoxError> {
    let socket = match &addr {
        SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };

    socket.set_reuseport(true)?;
    socket.bind(addr)?;
    let listener = socket.listen(1024)?;
    Ok(listener)
}

async fn get_information(headers: HeaderMap) -> impl IntoResponse {
    let info = InfoOutput {
        name: APP_NAME,
        version: APP_VERSION,
    };
    match Content::from(&headers) {
        Content::Json((), _) => Content::Json(info, None),
        Content::Cbor((), _) => Content::Cbor(info, None),
        _ => Content::Text(
            "supported content types: application/json, application/cbor".into(),
            Some(StatusCode::NOT_ACCEPTABLE),
        ),
    }
}

// Limit CPU work independently of Tokio's blocking-thread pool size.
static VERIFY_SLOTS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| {
    Arc::new(Semaphore::new(
        std::thread::available_parallelism().map_or(1, |n| n.get()),
    ))
});

type VerifyError = (StatusCode, String);

/// POST /verify
async fn post_verify(ct: Content<VerifyInput>) -> impl IntoResponse {
    let wants_cbor = matches!(ct, Content::Cbor(_, _));
    let req = match ct {
        Content::Cbor(req, _) | Content::Json(req, _) => req,
        _ => {
            return Content::Text(
                "supported content types: application/json, application/cbor".into(),
                Some(StatusCode::NOT_ACCEPTABLE),
            );
        }
    };

    match verify_with_limit(req, Arc::clone(&VERIFY_SLOTS)).await {
        Ok(out) if wants_cbor => Content::Cbor(out, None),
        Ok(out) => Content::Json(out, None),
        Err((status, err)) => Content::Text(err, Some(status)),
    }
}

async fn verify_with_limit(
    req: VerifyInput,
    slots: Arc<Semaphore>,
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
        verify_request(req)
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

fn verify_request(req: VerifyInput) -> Result<VerifyOutput, VerifyError> {
    let signed_envelope: SignedEnvelope =
        cbor_from_slice(req.signed_envelope.as_slice()).map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                format!("failed to decode signed_envelope CBOR: {err}"),
            )
        })?;
    // Read time when verification starts, after any wait for a CPU slot.
    signed_envelope
        .verify(
            unix_ms(),
            req.expect_target,
            req.expect_digest.as_ref().map(|d| d.as_slice()),
        )
        .map_err(|err| (StatusCode::UNAUTHORIZED, err))?;
    Ok(VerifyOutput {
        user: signed_envelope.sender(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use ic_auth_verifier::{BasicIdentity, Identity};

    async fn response_parts(
        response: axum::response::Response,
    ) -> (StatusCode, HeaderMap, bytes::Bytes) {
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, headers, body)
    }

    fn signed_verify_input() -> (VerifyInput, Principal) {
        let identity = BasicIdentity::from_raw_key(&[8u8; 32]);
        let envelope = SignedEnvelope::sign_message(&identity, b"hello world").unwrap();
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
            bytes::Bytes::from_static(
                b"supported content types: application/json, application/cbor"
            )
        );
    }

    #[tokio::test]
    async fn post_verify_accepts_valid_json_and_cbor() {
        let (input, user) = signed_verify_input();

        let (status, headers, body) = response_parts(
            post_verify(Content::Json(input.clone(), None))
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[http::header::CONTENT_TYPE], "application/json");
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["user"], user.to_text());

        let (status, headers, body) = response_parts(
            post_verify(Content::Cbor(input, None))
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[http::header::CONTENT_TYPE], "application/cbor");
        let value: VerifyOutput = cbor_from_slice(body.as_ref()).unwrap();
        assert_eq!(value.user, user);
    }

    #[tokio::test]
    async fn post_verify_rejects_unsupported_bad_and_unauthorized_inputs() {
        let (status, _, _) = response_parts(
            post_verify(Content::<VerifyInput>::Text("".to_string(), None))
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_ACCEPTABLE);

        let bad_cbor = VerifyInput {
            signed_envelope: vec![0xff].into(),
            expect_target: None,
            expect_digest: None,
        };
        let (status, _, body) = response_parts(
            post_verify(Content::Json(bad_cbor, None))
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
            post_verify(Content::Json(input, None))
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
    async fn create_listener_accepts_ephemeral_address() {
        assert_listener_or_permission("127.0.0.1:0").await;
        assert_listener_or_permission("[::1]:0").await;
    }

    async fn assert_listener_or_permission(addr: &str) {
        match create_reuse_port_listener(addr.parse().unwrap()).await {
            Ok(listener) => assert!(listener.local_addr().unwrap().port() > 0),
            Err(err) => {
                if err
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|err| err.kind() == std::io::ErrorKind::PermissionDenied)
                {
                    return;
                }
                panic!("unexpected listener error for {addr}: {err}");
            }
        }
    }

    #[tokio::test]
    async fn content_other_responses_for_handler_output_types() {
        let (status, headers, body) = response_parts(
            Content::<InfoOutput<'_>>::Other("application/xml".to_string(), None).into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(headers[http::header::CONTENT_TYPE], "text/plain");
        assert_eq!(
            body,
            bytes::Bytes::from_static(b"Unsupported MIME type: application/xml")
        );

        let (status, headers, body) = response_parts(
            Content::<VerifyOutput>::Other("application/xml".to_string(), None).into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(headers[http::header::CONTENT_TYPE], "text/plain");
        assert_eq!(
            body,
            bytes::Bytes::from_static(b"Unsupported MIME type: application/xml")
        );
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
        let mut pending = Box::pin(verify_with_limit(input, slots.clone()));
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
            verify_with_limit(bad, slots.clone()).await,
            Err((StatusCode::BAD_REQUEST, _))
        ));
        assert_eq!(slots.available_permits(), 1);
    }
}
