use ciborium::from_reader;
use ic_auth_types::{ByteBufB64, SignedDelegationCompact, deterministic_cbor_into_vec};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::str::FromStr;

/// Represents a request for deep linking between applications.
///
/// This struct is used to create deep link URLs for cross-application communication.
/// It can be used for various scenarios including:
/// - Authentication flows
/// - Launching specific UI interfaces in another application
/// - Opening form interfaces that return data to the calling application
/// - Other cross-application communication needs
///
/// # Type Parameters
///
/// * `'a` - The lifetime of string references in the struct
/// * `T` - The type of the payload, which must implement the [`Serialize`] trait
///
/// # Examples
///
/// ```
/// use ic_auth_verifier::deeplink::DeepLinkRequest;
/// use url::Url;
///
/// let request = DeepLinkRequest {
///     os: "ios",
///     action: "SignIn",
///     next_url: Some("https://example.com/callback"),
///     payload: Some("custom_data"),
/// };
///
/// let endpoint = Url::parse("https://auth.example.com").unwrap();
/// let deep_link_url = request.to_url(&endpoint);
/// ```
#[derive(Debug)]
pub struct DeepLinkRequest<'a, T: Serialize> {
    pub os: &'a str,     // e.g., "linux" | "windows" | "macos" | "ios" | "android"
    pub action: &'a str, // e.g., "SignIn"
    pub next_url: Option<&'a str>, // e.g., "https://anda.ai/deeplink"
    pub payload: Option<T>, // encode as base64url
}

impl<T> DeepLinkRequest<'_, T>
where
    T: Serialize,
{
    /// Converts the request into a URL with query parameters and fragment.
    ///
    /// This method creates a URL by appending the request parameters as query parameters
    /// and the serialized payload (if any) as a URL fragment. The payload is serialized
    /// to CBOR format and then encoded as base64url.
    ///
    /// # Parameters
    ///
    /// * `endpoint` - The base URL to which parameters will be added
    ///
    /// # Returns
    ///
    /// A new `url::Url` instance with the request parameters and payload
    ///
    /// # Panics
    ///
    /// This method will panic if the payload serialization to CBOR fails
    pub fn to_url(&self, endpoint: &url::Url) -> url::Url {
        let mut url = endpoint.clone();
        url.query_pairs_mut()
            .append_pair("os", self.os)
            .append_pair("action", self.action);

        if let Some(next_url) = self.next_url {
            url.query_pairs_mut().append_pair("next_url", next_url);
        }

        if let Some(payload) = &self.payload {
            let data =
                deterministic_cbor_into_vec(payload).expect("Failed to serialize payload to CBOR");
            url.set_fragment(Some(ByteBufB64(data).to_string().as_str()));
        }

        url
    }
}

/// Represents a response from a deep link interaction between applications.
///
/// This struct is used to parse and extract information from a URL received
/// after a deep link interaction. It can be used in various cross-application scenarios:
/// - Authentication flows
/// - Returning data from a form or UI interaction in another application
/// - Callback responses from any cross-application communication
///
/// # Examples
///
/// ```
/// use ic_auth_verifier::deeplink::DeepLinkResponse;
/// use url::Url;
///
/// let callback_url = Url::parse("https://example.com/callback?os=ios&action=SignIn#payload_data").unwrap();
/// let response = DeepLinkResponse::from_url(callback_url).unwrap();
/// ```
#[derive(Debug)]
pub struct DeepLinkResponse {
    pub url: url::Url,
    pub os: String,
    pub action: String,              // "SignIn"
    pub payload: Option<ByteBufB64>, // decode from base64url
}

impl DeepLinkResponse {
    /// Creates a new `DeepLinkResponse` from a URL.
    ///
    /// This method parses the URL to extract query parameters and fragment,
    /// constructing a `DeepLinkResponse` instance with the extracted information.
    ///
    /// # Parameters
    ///
    /// * `url` - The URL to parse, typically a callback URL from an application interaction
    ///
    /// # Returns
    ///
    /// A `Result` containing either the parsed `DeepLinkResponse` or an error message
    pub fn from_url(url: url::Url) -> Result<Self, String> {
        let mut query_pairs = url.query_pairs();
        let payload = match url.fragment() {
            Some(f) => Some(ByteBufB64::from_str(f).map_err(|err| format!("{err:?}"))?),
            None => None,
        };

        Ok(DeepLinkResponse {
            os: query_pairs
                .find(|(k, _)| k == "os")
                .map(|(_, v)| v.to_string())
                .unwrap_or_default(),
            action: query_pairs
                .find(|(k, _)| k == "action")
                .map(|(_, v)| v.to_string())
                .unwrap_or_default(),
            payload,
            url,
        })
    }

    /// Extracts and deserializes the payload from the response.
    ///
    /// This method attempts to deserialize the payload (if present) from CBOR format
    /// into the specified type `T`.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type to deserialize the payload into, which must implement [`DeserializeOwned`]
    ///
    /// # Returns
    ///
    /// A `Result` containing either the deserialized payload or an error message
    pub fn get_payload<T: DeserializeOwned>(&self) -> Result<T, String> {
        if let Some(payload) = &self.payload {
            Ok(from_reader(payload.as_slice()).map_err(|err| format!("{err:?}"))?)
        } else {
            Err("Payload is missing in the deep link response".to_string())
        }
    }
}

/// Represents a SignIn request payload for authentication.
///
/// This struct is used as the payload in a `DeepLinkRequest` for SignIn operations.
/// It contains the session public key and the maximum time-to-live for the session.
///
/// # Fields
///
/// * `session_pubkey` - The public key for the session
/// * `max_time_to_live` - The maximum time-to-live for the session in milliseconds
#[derive(Clone, Default, Deserialize, Serialize)]
pub struct SignInRequest {
    #[serde(rename = "s")]
    pub session_pubkey: ByteBufB64,
    #[serde(rename = "m")]
    pub max_time_to_live: u64, // in milliseconds
}

/// Represents a SignIn response payload from authentication.
///
/// This struct is used as the payload in a `DeepLinkResponse` for SignIn operations.
/// It contains the user's public key, delegations, authentication method, and origin.
///
/// # Fields
///
/// * `user_pubkey` - The user's public key
/// * `delegations` - A vector of signed delegations that authorize the session
/// * `authn_method` - The authentication method used (e.g., "webauthn", "passkey")
/// * `origin` - The origin of the authentication request
#[derive(Clone, Default, Deserialize, Serialize)]
pub struct SignInResponse {
    #[serde(rename = "u")]
    pub user_pubkey: ByteBufB64,
    #[serde(rename = "d")]
    pub delegations: Vec<SignedDelegationCompact>,
    #[serde(rename = "a")]
    pub authn_method: String,
    #[serde(rename = "o")]
    pub origin: String,
}
