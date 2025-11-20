use axum::{BoxError, Router, http::StatusCode, response::IntoResponse, routing};
use candid::Principal;
use ciborium::from_reader;
use http::HeaderMap;
use ic_auth_types::{ByteArrayB64, ByteBufB64};
use ic_auth_verifier::SignedEnvelope;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use structured_logger::{Builder, async_json::new_writer, get_env_level, unix_ms};
use tokio::signal;
use tokio_util::sync::CancellationToken;

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
#[tokio::main]
async fn main() -> Result<(), BoxError> {
    // Initialize structured logging with Json format
    Builder::with_level(&get_env_level().to_string())
        .with_target_writer("*", new_writer(tokio::io::stdout()))
        .init();

    let signal = shutdown_signal(CancellationToken::new());
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

pub async fn shutdown_signal(cancel_token: CancellationToken) {
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
    cancel_token.cancel();
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

    match signed_envelope.verify(
        now_ms,
        req.expect_target,
        req.expect_digest.as_ref().map(|d| d.as_slice()),
    ) {
        Ok(_) => {}
        Err(err) => {
            return Content::Text(format!("{err:?}"), Some(StatusCode::UNAUTHORIZED));
        }
    };
    let out = VerifyOutput {
        user: Principal::self_authenticating(&signed_envelope.pubkey),
    };

    match &ct {
        Content::Cbor(_, _) => Content::Cbor(out, None),
        Content::Json(_, _) => Content::Json(out, None),
        _ => Content::Text(
            "supported content types: application/json, application/cbor".into(),
            Some(StatusCode::NOT_ACCEPTABLE),
        ),
    }
}
