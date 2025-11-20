use axum_core::{
    extract::{FromRequest, Request},
    response::{IntoResponse, Response},
};
use bytes::{BufMut, Bytes, BytesMut};
use http::{
    StatusCode,
    header::{self, HeaderMap, HeaderValue},
};
use serde::{Serialize, de::DeserializeOwned};

pub static CONTENT_TYPE_Cbor: &str = "application/cbor";
pub static CONTENT_TYPE_Json: &str = "application/json";
pub static CONTENT_TYPE_TEXT: &str = "text/plain";
pub enum Content<T> {
    Json(T, Option<StatusCode>),
    Cbor(T, Option<StatusCode>),
    Text(String, Option<StatusCode>),
    Other(String, Option<StatusCode>),
}

impl Content<()> {
    pub fn from(headers: &HeaderMap) -> Self {
        if let Some(ct) = Self::from_content_type(headers) {
            return ct;
        }

        if let Some(accept) = headers.get(header::ACCEPT)
            && let Ok(accept) = accept.to_str()
        {
            if accept.contains(CONTENT_TYPE_Cbor) {
                return Content::Cbor((), None);
            }
            if accept.contains(CONTENT_TYPE_Json) {
                return Content::Json((), None);
            }
            if accept.contains(CONTENT_TYPE_TEXT) {
                return Content::Text("".to_string(), None);
            }
            return Content::Other(accept.to_string(), None);
        }

        Content::Other("unknown".to_string(), None)
    }

    pub fn from_content_type(headers: &HeaderMap) -> Option<Self> {
        if let Some(content_type) = headers.get(header::CONTENT_TYPE)
            && let Ok(content_type) = content_type.to_str()
            && let Ok(mime) = content_type.parse::<mime::Mime>()
            && mime.type_() == "application"
        {
            if mime.subtype() == "cbor" || mime.suffix().is_some_and(|name| name == "cbor") {
                return Some(Content::Cbor((), None));
            } else if mime.subtype() == "json" || mime.suffix().is_some_and(|name| name == "json") {
                return Some(Content::Json((), None));
            }
        }

        None
    }
}

impl<S, T> FromRequest<S> for Content<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Content::from(req.headers()) {
            Content::Json(_, _) => {
                let body = Bytes::from_request(req, state)
                    .await
                    .map_err(IntoResponse::into_response)?;
                let value: T = serde_json::from_slice(&body).map_err(|err| {
                    Content::Text::<String>(err.to_string(), Some(StatusCode::BAD_REQUEST))
                        .into_response()
                })?;
                Ok(Self::Json(value, None))
            }
            Content::Cbor(_, _) => {
                let body = Bytes::from_request(req, state)
                    .await
                    .map_err(IntoResponse::into_response)?;
                let value: T = ciborium::from_reader(&body[..]).map_err(|err| {
                    Content::Text::<String>(err.to_string(), Some(StatusCode::BAD_REQUEST))
                        .into_response()
                })?;
                Ok(Self::Cbor(value, None))
            }
            _ => Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()),
        }
    }
}

impl<T> IntoResponse for Content<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        let mut buf = BytesMut::with_capacity(128).writer();
        match self {
            Self::Json(v, c) => match serde_json::to_writer(&mut buf, &v) {
                Ok(()) => (
                    c.unwrap_or_default(),
                    [(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static(CONTENT_TYPE_Json),
                    )],
                    buf.into_inner().freeze(),
                )
                    .into_response(),
                Err(err) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static(CONTENT_TYPE_TEXT),
                    )],
                    err.to_string(),
                )
                    .into_response(),
            },
            Self::Cbor(v, c) => match ciborium::into_writer(&v, &mut buf) {
                Ok(()) => (
                    c.unwrap_or_default(),
                    [(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static(CONTENT_TYPE_Cbor),
                    )],
                    buf.into_inner().freeze(),
                )
                    .into_response(),
                Err(err) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static(CONTENT_TYPE_TEXT),
                    )],
                    err.to_string(),
                )
                    .into_response(),
            },
            Self::Text(v, c) => (
                c.unwrap_or_default(),
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(CONTENT_TYPE_TEXT),
                )],
                v,
            )
                .into_response(),
            Self::Other(v, c) => (
                c.unwrap_or(StatusCode::UNSUPPORTED_MEDIA_TYPE),
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(CONTENT_TYPE_TEXT),
                )],
                format!("Unsupported MIME type: {}", v),
            )
                .into_response(),
        }
    }
}
