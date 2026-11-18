use axum::{
    body::Bytes,
    extract::{FromRequest, Request},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use ic_auth_types::{cbor_from_slice, cbor_into_vec};
use serde::{Serialize, de::DeserializeOwned};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Format {
    Json,
    Cbor,
}

impl Format {
    fn from_mime(mime: &mime::Mime) -> Option<Self> {
        if mime.type_() != mime::APPLICATION {
            return None;
        }
        match mime.suffix().unwrap_or(mime.subtype()).as_str() {
            "json" => Some(Self::Json),
            "cbor" => Some(Self::Cbor),
            _ => None,
        }
    }

    fn from_content_type(headers: &HeaderMap) -> Option<Self> {
        let mime = headers
            .get(header::CONTENT_TYPE)?
            .to_str()
            .ok()?
            .parse()
            .ok()?;
        Self::from_mime(&mime)
    }

    /// GET / uses Content-Type first, then the acceptable format with highest quality.
    pub fn for_response(headers: &HeaderMap) -> Option<Self> {
        if let Some(format) = Self::from_content_type(headers) {
            return Some(format);
        }
        if !headers.contains_key(header::ACCEPT) {
            return Some(Self::Json);
        }

        // A more specific range overrides a wildcard, even at q=0.
        let mut candidates: [Option<(u8, f32)>; 2] = [None, None];
        for line in headers.get_all(header::ACCEPT) {
            for range in line.to_str().ok()?.split(',') {
                let Ok(mime) = range.trim().parse::<mime::Mime>() else {
                    continue;
                };
                let quality = match mime.get_param("q") {
                    Some(q) => match q.as_str().parse::<f32>() {
                        Ok(q) if (0.0..=1.0).contains(&q) => q,
                        _ => continue,
                    },
                    None => 1.0,
                };
                let exact = Self::from_mime(&mime);
                for (format, candidate) in [Self::Json, Self::Cbor].into_iter().zip(&mut candidates)
                {
                    let specificity = match mime.essence_str() {
                        "*/*" => 0,
                        "application/*" => 1,
                        _ if exact == Some(format) => 2,
                        _ => continue,
                    };
                    if candidate.is_none_or(|previous| (specificity, quality) > previous) {
                        *candidate = Some((specificity, quality));
                    }
                }
            }
        }
        let [json, cbor] = candidates.map(|candidate| candidate.filter(|(_, q)| *q > 0.0));
        match (json, cbor) {
            (None, None) => None,
            (Some(_), None) => Some(Self::Json),
            (None, Some(_)) => Some(Self::Cbor),
            (Some((js, jq)), Some((cs, cq))) => {
                // Explicit CBOR wins a tie. Wildcard ties use the JSON default.
                if cq > jq || (cq == jq && (cs > js || cs == 2)) {
                    Some(Self::Cbor)
                } else {
                    Some(Self::Json)
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct Content<T>(pub Format, pub T);

impl<S, T> FromRequest<S> for Content<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let format = Format::from_content_type(req.headers())
            .ok_or_else(|| StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response())?;
        let body = Bytes::from_request(req, state)
            .await
            .map_err(IntoResponse::into_response)?;
        let value = match format {
            Format::Json => serde_json::from_slice(&body).map_err(|err| err.to_string()),
            Format::Cbor => cbor_from_slice(&body),
        }
        .map_err(|err| text_response(StatusCode::BAD_REQUEST, err))?;
        Ok(Self(format, value))
    }
}

impl<T: Serialize> IntoResponse for Content<T> {
    fn into_response(self) -> Response {
        let (content_type, body) = match self.0 {
            Format::Json => (
                "application/json",
                serde_json::to_vec(&self.1).map_err(|err| err.to_string()),
            ),
            Format::Cbor => ("application/cbor", cbor_into_vec(&self.1)),
        };
        match body {
            Ok(body) => ([(header::CONTENT_TYPE, content_type)], body).into_response(),
            Err(err) => text_response(StatusCode::INTERNAL_SERVER_ERROR, err),
        }
    }
}

pub fn text_response(status: StatusCode, body: String) -> Response {
    (status, [(header::CONTENT_TYPE, "text/plain")], body).into_response()
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
        headers.insert(header::ACCEPT, "application/cbor".parse().unwrap());
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        assert_eq!(Format::for_response(&headers), Some(Format::Json));

        headers.insert(
            header::CONTENT_TYPE,
            "application/vnd.example+cbor".parse().unwrap(),
        );
        assert_eq!(Format::for_response(&headers), Some(Format::Cbor));

        headers.remove(header::CONTENT_TYPE);
        assert_eq!(Format::for_response(&headers), Some(Format::Cbor));

        headers.insert(header::ACCEPT, "text/plain".parse().unwrap());
        assert_eq!(Format::for_response(&headers), None);

        headers.insert(header::ACCEPT, "application/xml".parse().unwrap());
        assert_eq!(Format::for_response(&headers), None);

        // No `Accept` means any media type is acceptable (RFC 9110 12.5.1).
        headers.clear();
        assert_eq!(Format::for_response(&headers), Some(Format::Json));
    }

    #[test]
    fn accept_wildcards_and_quality_values_are_honoured() {
        let pick = |accept: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT, accept.parse().unwrap());
            Format::for_response(&headers)
        };

        // Wildcards resolve to JSON rather than failing negotiation, so curl
        // (`*/*`) and browsers get a readable body instead of `406`.
        assert_eq!(pick("*/*"), Some(Format::Json));
        assert_eq!(pick("application/*"), Some(Format::Json));
        assert_eq!(
            pick("text/html,application/xhtml+xml,*/*;q=0.8"),
            Some(Format::Json)
        );

        // q-values decide, instead of the order the code happens to check in.
        assert_eq!(
            pick("application/json;q=0.9, application/cbor;q=0.1"),
            Some(Format::Json)
        );
        assert_eq!(
            pick("application/json;q=0.1, application/cbor;q=0.9"),
            Some(Format::Cbor)
        );
        // `q=0` is a refusal, not a request.
        assert_eq!(
            pick("application/cbor;q=0, application/json"),
            Some(Format::Json)
        );
        assert_eq!(pick("application/cbor;q=0"), None);

        // Equal quality keeps the historical CBOR > JSON preference.
        assert_eq!(
            pick("application/json, application/cbor"),
            Some(Format::Cbor)
        );
        assert_eq!(pick("text/plain"), None);

        // A distinct type that merely contains a supported name is not a match.
        assert_eq!(pick("application/cbor-seq"), None);
        assert_eq!(pick("application/xml"), None);
        // Structured suffixes still work.
        assert_eq!(pick("application/vnd.example+cbor"), Some(Format::Cbor));
        assert_eq!(pick("application/cbor+json"), Some(Format::Json));
        assert_eq!(pick("application/json+xml"), None);
        // Malformed ranges are skipped rather than aborting negotiation.
        assert_eq!(pick("not a mime, application/json"), Some(Format::Json));
    }

    #[test]
    fn content_type_parser_ignores_unsupported_or_invalid_values() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "text/json".parse().unwrap());
        assert!(Format::from_content_type(&headers).is_none());

        headers.insert(header::CONTENT_TYPE, "application/xml".parse().unwrap());
        assert!(Format::from_content_type(&headers).is_none());

        headers.insert(
            header::CONTENT_TYPE,
            "application/problem+json".parse().unwrap(),
        );
        assert_eq!(Format::from_content_type(&headers), Some(Format::Json));

        headers.insert(
            header::CONTENT_TYPE,
            "application/json+cbor".parse().unwrap(),
        );
        assert_eq!(Format::from_content_type(&headers), Some(Format::Cbor));
        headers.insert(
            header::CONTENT_TYPE,
            "application/json+xml".parse().unwrap(),
        );
        assert_eq!(Format::from_content_type(&headers), None);

        headers.insert(header::CONTENT_TYPE, "not a mime".parse().unwrap());
        assert!(Format::from_content_type(&headers).is_none());
    }

    #[tokio::test]
    async fn from_request_decodes_json_and_cbor() {
        let payload = Payload {
            value: "hello".to_string(),
        };
        let body = serde_json::to_vec(&payload).unwrap();
        let request = Request::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();

        let parsed = Content::<Payload>::from_request(request, &())
            .await
            .unwrap();
        assert_eq!(parsed.0, Format::Json);
        assert_eq!(parsed.1, payload);

        let body = cbor_into_vec(&payload).unwrap();
        let request = Request::builder()
            .header(header::CONTENT_TYPE, "application/cbor")
            .body(Body::from(body))
            .unwrap();

        match Content::<Payload>::from_request(request, &())
            .await
            .unwrap()
        {
            Content(Format::Cbor, value) => assert_eq!(value, payload),
            other => panic!("unexpected content: {other:?}"),
        }
    }

    #[tokio::test]
    async fn from_request_rejects_bad_or_unsupported_bodies() {
        let request = Request::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{"))
            .unwrap();
        let response = Content::<Payload>::from_request(request, &())
            .await
            .unwrap_err();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let request = Request::builder()
            .header(header::CONTENT_TYPE, "application/cbor")
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

        // `Accept` describes the response and must not choose the request
        // parser: a `text/plain` body is rejected even when JSON is accepted.
        let request = Request::builder()
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::ACCEPT, "application/json")
            .body(Body::from(r#"{"value":"hello"}"#))
            .unwrap();
        let response = Content::<Payload>::from_request(request, &())
            .await
            .unwrap_err();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn into_response_reports_serialization_errors() {
        for format in [Format::Json, Format::Cbor] {
            let (status, headers, body) =
                response_parts(Content(format, FailingSerialize).into_response()).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(headers[header::CONTENT_TYPE], "text/plain");
            assert!(
                std::str::from_utf8(&body)
                    .unwrap()
                    .contains("intentional serialize failure")
            );
        }
    }
}
