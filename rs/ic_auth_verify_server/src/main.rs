use axum::{BoxError, http::StatusCode, response::IntoResponse};
#[cfg(not(test))]
use axum::{Router, routing};
use candid::Principal;
use ciborium::from_reader;
use http::HeaderMap;
use ic_auth_types::{ByteArrayB64, ByteBufB64};
use ic_auth_verifier::SignedEnvelope;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use structured_logger::unix_ms;
#[cfg(not(test))]
use structured_logger::{Builder, async_json::new_writer, get_env_level};
#[cfg(not(test))]
use tokio::signal;

mod content;
use content::Content;

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Deserialize, Serialize)]
struct VerifyInput {
    signed_envelope: ByteBufB64,
    expect_target: Option<Principal>,
    expect_digest: Option<ByteArrayB64<32>>,
}

#[derive(Clone, Deserialize, Serialize)]
struct VerifyOutput {
    user: Principal,
}

#[derive(Clone, Serialize)]
struct InfoOutput<'a> {
    name: &'a str,
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

/// POST /verify
async fn post_verify(ct: Content<VerifyInput>) -> impl IntoResponse {
    let wants_cbor = matches!(ct, Content::Cbor(_, _));
    let req = match &ct {
        Content::Cbor(req, _) => req,
        Content::Json(req, _) => req,
        _ => {
            return Content::Text(
                "supported content types: application/json, application/cbor".into(),
                Some(StatusCode::NOT_ACCEPTABLE),
            );
        }
    };

    let now_ms = unix_ms();
    let signed_envelope: SignedEnvelope = match from_reader(req.signed_envelope.as_slice()) {
        Ok(se) => se,
        Err(err) => {
            return Content::Text(
                format!("failed to decode signed_envelope Cbor: {err:?}"),
                Some(StatusCode::BAD_REQUEST),
            );
        }
    };

    if let Err(err) = signed_envelope.verify(
        now_ms,
        req.expect_target,
        req.expect_digest.as_ref().map(|d| d.as_slice()),
    ) {
        return Content::Text(err, Some(StatusCode::UNAUTHORIZED));
    }
    let out = VerifyOutput {
        user: Principal::self_authenticating(&signed_envelope.pubkey),
    };

    if wants_cbor {
        Content::Cbor(out, None)
    } else {
        Content::Json(out, None)
    }
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
            ciborium::from_reader(body.as_ref()).unwrap();
        assert_eq!(value["name"], APP_NAME);
        assert_eq!(value["version"], APP_VERSION);

        let (status, _, body) =
            response_parts(get_information(HeaderMap::new()).await.into_response()).await;
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
        let value: VerifyOutput = ciborium::from_reader(body.as_ref()).unwrap();
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
                .contains("failed to decode signed_envelope Cbor")
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
}
