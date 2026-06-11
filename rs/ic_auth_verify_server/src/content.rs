use axum_core::{
    extract::{FromRequest, Request},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use http::{
    StatusCode,
    header::{self, HeaderMap, HeaderValue},
};
use serde::{Serialize, de::DeserializeOwned};

pub static CONTENT_TYPE_CBOR: &str = "application/cbor";
pub static CONTENT_TYPE_JSON: &str = "application/json";
pub static CONTENT_TYPE_TEXT: &str = "text/plain";

#[derive(Debug)]
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
            if accept.contains(CONTENT_TYPE_CBOR) {
                return Content::Cbor((), None);
            }
            if accept.contains(CONTENT_TYPE_JSON) {
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
        match self {
            Self::Json(v, c) => serialized_response(
                c.unwrap_or_default(),
                CONTENT_TYPE_JSON,
                serde_json::to_vec(&v)
                    .map(Bytes::from)
                    .map_err(|err| err.to_string()),
            ),
            Self::Cbor(v, c) => {
                let mut buf = Vec::new();
                let body = ciborium::into_writer(&v, &mut buf)
                    .map(|()| Bytes::from(buf))
                    .map_err(|err| err.to_string());
                serialized_response(c.unwrap_or_default(), CONTENT_TYPE_CBOR, body)
            }
            Self::Text(v, c) => text_response(c.unwrap_or_default(), v),
            Self::Other(v, c) => text_response(
                c.unwrap_or(StatusCode::UNSUPPORTED_MEDIA_TYPE),
                format!("Unsupported MIME type: {}", v),
            ),
        }
    }
}

fn serialized_response(
    status: StatusCode,
    content_type: &'static str,
    body: Result<Bytes, String>,
) -> Response {
    match body {
        Ok(body) => (
            status,
            [(header::CONTENT_TYPE, HeaderValue::from_static(content_type))],
            body,
        )
            .into_response(),
        Err(err) => text_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

fn text_response(status: StatusCode, body: String) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static(CONTENT_TYPE_TEXT),
        )],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use serde::{Deserialize, Serializer, ser::Error as _};

    #[derive(Debug, Deserialize, PartialEq, Serialize)]
    struct Payload {
        value: String,
    }

    struct FailingSerialize;

    impl Serialize for FailingSerialize {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Err(S::Error::custom("intentional serialize failure"))
        }
    }

    async fn response_parts(response: Response) -> (StatusCode, HeaderMap, Bytes) {
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, headers, body)
    }

    #[test]
    fn content_from_prefers_content_type_then_accept() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, CONTENT_TYPE_CBOR.parse().unwrap());
        headers.insert(header::CONTENT_TYPE, CONTENT_TYPE_JSON.parse().unwrap());
        assert!(matches!(Content::from(&headers), Content::Json((), None)));

        headers.insert(
            header::CONTENT_TYPE,
            "application/vnd.example+cbor".parse().unwrap(),
        );
        assert!(matches!(Content::from(&headers), Content::Cbor((), None)));

        headers.remove(header::CONTENT_TYPE);
        assert!(matches!(Content::from(&headers), Content::Cbor((), None)));

        headers.insert(header::ACCEPT, CONTENT_TYPE_TEXT.parse().unwrap());
        assert!(matches!(Content::from(&headers), Content::Text(_, None)));

        headers.insert(header::ACCEPT, "application/xml".parse().unwrap());
        assert!(matches!(Content::from(&headers), Content::Other(_, None)));

        headers.clear();
        assert!(matches!(Content::from(&headers), Content::Other(_, None)));
    }

    #[test]
    fn content_type_parser_ignores_unsupported_or_invalid_values() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "text/json".parse().unwrap());
        assert!(Content::from_content_type(&headers).is_none());

        headers.insert(header::CONTENT_TYPE, "application/xml".parse().unwrap());
        assert!(Content::from_content_type(&headers).is_none());

        headers.insert(
            header::CONTENT_TYPE,
            "application/problem+json".parse().unwrap(),
        );
        assert!(matches!(
            Content::from_content_type(&headers),
            Some(Content::Json((), None))
        ));

        headers.insert(header::CONTENT_TYPE, "not a mime".parse().unwrap());
        assert!(Content::from_content_type(&headers).is_none());
    }

    #[tokio::test]
    async fn from_request_decodes_json_and_cbor() {
        let payload = Payload {
            value: "hello".to_string(),
        };
        let body = serde_json::to_vec(&payload).unwrap();
        let request = Request::builder()
            .header(header::CONTENT_TYPE, CONTENT_TYPE_JSON)
            .body(Body::from(body))
            .unwrap();

        let parsed = Content::<Payload>::from_request(request, &())
            .await
            .unwrap();
        assert!(matches!(parsed, Content::Json(_, None)));
        if let Content::Json(value, None) = parsed {
            assert_eq!(value, payload);
        }

        let mut body = Vec::new();
        ciborium::into_writer(&payload, &mut body).unwrap();
        let request = Request::builder()
            .header(header::CONTENT_TYPE, CONTENT_TYPE_CBOR)
            .body(Body::from(body))
            .unwrap();

        match Content::<Payload>::from_request(request, &())
            .await
            .unwrap()
        {
            Content::Cbor(value, None) => assert_eq!(value, payload),
            other => panic!("unexpected content: {other:?}"),
        }
    }

    #[tokio::test]
    async fn from_request_rejects_bad_or_unsupported_bodies() {
        let request = Request::builder()
            .header(header::CONTENT_TYPE, CONTENT_TYPE_JSON)
            .body(Body::from("{"))
            .unwrap();
        let response = Content::<Payload>::from_request(request, &())
            .await
            .unwrap_err();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let request = Request::builder()
            .header(header::CONTENT_TYPE, CONTENT_TYPE_CBOR)
            .body(Body::from(vec![0xff]))
            .unwrap();
        let response = Content::<Payload>::from_request(request, &())
            .await
            .unwrap_err();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let request = Request::builder().body(Body::empty()).unwrap();
        let response = Content::<Payload>::from_request(request, &())
            .await
            .unwrap_err();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn into_response_sets_status_headers_and_body() {
        let payload = Payload {
            value: "hello".to_string(),
        };

        let (status, headers, body) =
            response_parts(Content::Json(&payload, Some(StatusCode::CREATED)).into_response())
                .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(headers[header::CONTENT_TYPE], CONTENT_TYPE_JSON);
        assert_eq!(body, Bytes::from_static(br#"{"value":"hello"}"#));

        let (status, headers, body) =
            response_parts(Content::Cbor(&payload, Some(StatusCode::ACCEPTED)).into_response())
                .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(headers[header::CONTENT_TYPE], CONTENT_TYPE_CBOR);
        let decoded: Payload = ciborium::from_reader(body.as_ref()).unwrap();
        assert_eq!(decoded, payload);

        let (status, headers, body) = response_parts(
            Content::<Payload>::Text("plain".to_string(), Some(StatusCode::IM_A_TEAPOT))
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::IM_A_TEAPOT);
        assert_eq!(headers[header::CONTENT_TYPE], CONTENT_TYPE_TEXT);
        assert_eq!(body, Bytes::from_static(b"plain"));

        let (status, headers, body) = response_parts(
            Content::<Payload>::Other("image/png".to_string(), None).into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(headers[header::CONTENT_TYPE], CONTENT_TYPE_TEXT);
        assert_eq!(
            body,
            Bytes::from_static(b"Unsupported MIME type: image/png")
        );
    }

    #[tokio::test]
    async fn into_response_reports_serialization_errors() {
        let (status, headers, body) =
            response_parts(Content::Json(FailingSerialize, None).into_response()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(headers[header::CONTENT_TYPE], CONTENT_TYPE_TEXT);
        assert_eq!(body, Bytes::from_static(b"intentional serialize failure"));

        let (status, headers, body) =
            response_parts(Content::Cbor(FailingSerialize, None).into_response()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(headers[header::CONTENT_TYPE], CONTENT_TYPE_TEXT);
        assert!(
            std::str::from_utf8(&body)
                .unwrap()
                .contains("intentional serialize failure")
        );
    }

    #[tokio::test]
    async fn into_response_covers_owned_payload_and_marker_variants() {
        let payload = Payload {
            value: "owned".to_string(),
        };

        let (status, headers, body) =
            response_parts(Content::Json(payload, None).into_response()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CONTENT_TYPE], CONTENT_TYPE_JSON);
        assert_eq!(body, Bytes::from_static(br#"{"value":"owned"}"#));

        let payload = Payload {
            value: "owned".to_string(),
        };
        let (status, headers, body) =
            response_parts(Content::Cbor(payload, None).into_response()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CONTENT_TYPE], CONTENT_TYPE_CBOR);
        let decoded: Payload = ciborium::from_reader(body.as_ref()).unwrap();
        assert_eq!(
            decoded,
            Payload {
                value: "owned".to_string(),
            }
        );

        let (status, headers, body) = response_parts(
            Content::<FailingSerialize>::Text("fallback".to_string(), None).into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CONTENT_TYPE], CONTENT_TYPE_TEXT);
        assert_eq!(body, Bytes::from_static(b"fallback"));

        let (status, headers, body) = response_parts(
            Content::<FailingSerialize>::Other("application/octet-stream".to_string(), None)
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(headers[header::CONTENT_TYPE], CONTENT_TYPE_TEXT);
        assert_eq!(
            body,
            Bytes::from_static(b"Unsupported MIME type: application/octet-stream")
        );

        let (status, headers, body) =
            response_parts(Content::<String>::Other("video/mp4".to_string(), None).into_response())
                .await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(headers[header::CONTENT_TYPE], CONTENT_TYPE_TEXT);
        assert_eq!(
            body,
            Bytes::from_static(b"Unsupported MIME type: video/mp4")
        );
    }
}
