//! Sans-I/O client for the BIP77 directory mailbox REST API.
//!
//! [`Client::get`] and [`Client::post`] return an [`OhttpRequest`] for the
//! caller to send to the relay, and a context. The caller passes the relay's
//! response body to the context, which returns the result.

use std::fmt;

use bech32::{Hrp, NoChecksum};
use ohttp_client::{OhttpClient, Response, ResponseContext};

use crate::{KeyConfig, OhttpRequest, Url};

/// BHTTP request size that BIP77 pads to, so the encapsulated request is
/// [`ENCAPSULATED_MESSAGE_BYTES`].
pub const PADDED_BHTTP_REQUEST_BYTES: usize = 8104;

/// Size of every encapsulated directory request and response.
pub const ENCAPSULATED_MESSAGE_BYTES: usize = 8192;

/// A 64-bit mailbox identifier.
///
/// Displayed as the 13 uppercase bech32 characters that BIP77 uses in
/// mailbox paths, without the human-readable part, separator or checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShortId(pub [u8; 8]);

impl fmt::Display for ShortId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // bech32 has no way to encode only the data part, so this encodes
        // with a placeholder human-readable part and strips it.
        let hrp = Hrp::parse_unchecked("ID");
        let encoded = bech32::encode_upper::<NoChecksum>(hrp, &self.0)
            .expect("8 bytes are within the bech32 length limit");
        f.write_str(&encoded["ID1".len()..])
    }
}

/// A client for one directory, reached through one OHTTP relay.
#[derive(Debug, Clone)]
pub struct Client(OhttpClient);

/// Decodes the response to a [`Client::get`] request.
pub struct GetContext(ResponseContext);

/// Decodes the response to a [`Client::post`] request.
pub struct PostContext(ResponseContext);

/// Failure to build a request or decode its response.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// BHTTP encoding, OHTTP encapsulation, or the reverse failed.
    #[error("OHTTP: {0}")]
    Ohttp(#[from] ohttp_client::Error),
    /// The encapsulated response is not [`ENCAPSULATED_MESSAGE_BYTES`] long.
    #[error("encapsulated response has size {0}, expected {ENCAPSULATED_MESSAGE_BYTES}")]
    ResponseSize(usize),
    /// The directory answered with a status the request does not define.
    #[error("directory returned unexpected status {0}")]
    UnexpectedStatus(u16),
}

/// A URL is not HTTP(S), has no host, or has credentials or a fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UnsupportedUrl {
    /// The relay URL.
    #[error("unsupported relay URL")]
    Relay,
    /// The directory URL.
    #[error("unsupported directory URL")]
    Directory,
}

fn is_supported(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}

impl Client {
    /// Mailbox paths are appended to `directory`'s path.
    ///
    /// `key_config` is the directory gateway's OHTTP key configuration.
    pub fn new(relay: Url, directory: Url, key_config: KeyConfig) -> Result<Self, UnsupportedUrl> {
        if !is_supported(&relay) {
            return Err(UnsupportedUrl::Relay);
        }
        if !is_supported(&directory) {
            return Err(UnsupportedUrl::Directory);
        }
        Ok(Self(
            OhttpClient::new(relay, directory, key_config).known_length(PADDED_BHTTP_REQUEST_BYTES),
        ))
    }

    /// Build a GET request for mailbox `id`.
    ///
    /// The directory holds the request open until the mailbox has a payload or
    /// it times out.
    pub fn get(&self, id: ShortId) -> Result<(OhttpRequest, GetContext), Error> {
        let (request, context) = self.encapsulate("GET", id, None)?;
        Ok((request, GetContext(context)))
    }

    /// Build a POST request of `payload` to mailbox `id`.
    pub fn post(&self, id: ShortId, payload: &[u8]) -> Result<(OhttpRequest, PostContext), Error> {
        let (request, context) = self.encapsulate("POST", id, Some(payload))?;
        Ok((request, PostContext(context)))
    }

    fn encapsulate(
        &self,
        method: &str,
        id: ShortId,
        body: Option<&[u8]>,
    ) -> Result<(OhttpRequest, ResponseContext), Error> {
        Ok(self
            .0
            .encapsulate(method, &format!("/{id}"), &[], &[], body)?)
    }
}

impl GetContext {
    /// The payload, or `None` if the directory timed out before the mailbox
    /// had one.
    pub fn finish(self, response: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let response = decapsulate(self.0, response)?;
        match response.status() {
            200 => Ok(Some(response.into_body())),
            202 => Ok(None),
            status => Err(Error::UnexpectedStatus(status)),
        }
    }
}

impl PostContext {
    pub fn finish(self, response: &[u8]) -> Result<(), Error> {
        let response = decapsulate(self.0, response)?;
        match response.status() {
            200 => Ok(()),
            status => Err(Error::UnexpectedStatus(status)),
        }
    }
}

fn decapsulate(context: ResponseContext, response: &[u8]) -> Result<Response, Error> {
    if response.len() != ENCAPSULATED_MESSAGE_BYTES {
        return Err(Error::ResponseSize(response.len()));
    }
    Ok(context.decapsulate(response)?)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::io::Cursor;

    use bhttp::{Message, Mode, StatusCode};
    use bitcoin_ohttp::hpke::{Aead, Kdf, Kem};
    use bitcoin_ohttp::{Server, ServerResponse, SymmetricSuite};

    use super::*;

    /// Response BHTTP size that encapsulates to [`ENCAPSULATED_MESSAGE_BYTES`]:
    /// a 32-byte nonce and a 16-byte AEAD tag are added.
    const PADDED_BHTTP_RESPONSE_BYTES: usize = ENCAPSULATED_MESSAGE_BYTES - 32 - 16;

    /// An OHTTP gateway with BIP77's secp256k1 KEM.
    fn gateway() -> Server {
        let config = bitcoin_ohttp::KeyConfig::new(
            1,
            Kem::K256Sha256,
            vec![SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)],
        )
        .unwrap();
        Server::new(config).unwrap()
    }

    fn try_client(gateway: &Server, directory: &str) -> Result<Client, UnsupportedUrl> {
        Client::new(
            Url::parse("https://relay.example/").unwrap(),
            Url::parse(directory).unwrap(),
            gateway.config().clone().into(),
        )
    }

    fn client(gateway: &Server, directory: &str) -> Client {
        try_client(gateway, directory).unwrap()
    }

    /// Decapsulate `request` as the gateway, returning the padded BHTTP request
    /// and the context for its response.
    fn receive(gateway: &Server, request: &OhttpRequest) -> (Vec<u8>, ServerResponse) {
        gateway.decapsulate(&request.body).unwrap()
    }

    fn read_request(bhttp: &[u8]) -> Message {
        Message::read_bhttp(&mut Cursor::new(bhttp)).unwrap()
    }

    /// Encapsulate a response as the gateway, padded as BIP77 requires.
    fn respond(context: ServerResponse, status: u16, body: &[u8]) -> Vec<u8> {
        let mut message = Message::response(StatusCode::try_from(status).unwrap());
        message.write_content(body);
        let mut bhttp = Vec::new();
        message.write_bhttp(Mode::KnownLength, &mut bhttp).unwrap();
        bhttp.resize(PADDED_BHTTP_RESPONSE_BYTES, 0);
        context.encapsulate(&bhttp).unwrap()
    }

    #[test]
    fn short_id_vectors() {
        assert_eq!(ShortId([0; 8]).to_string(), "QQQQQQQQQQQQQ");
        // 64 one bits and one zero padding bit.
        assert_eq!(ShortId([0xff; 8]).to_string(), "LLLLLLLLLLLL7");
    }

    #[test]
    fn get_requests_the_mailbox_path() {
        let gateway = gateway();
        let id = ShortId([1; 8]);
        let (request, _) = client(&gateway, "https://directory.example/")
            .get(id)
            .unwrap();
        assert_eq!(request.url.as_str(), "https://relay.example/");

        let (bhttp, _) = receive(&gateway, &request);
        let inner = read_request(&bhttp);
        let control = inner.control();
        assert_eq!(control.method(), Some(&b"GET"[..]));
        assert_eq!(control.authority(), Some(&b"directory.example"[..]));
        assert_eq!(control.path(), Some(format!("/{id}").as_bytes()));
        assert!(inner.content().is_empty());
    }

    #[test]
    fn post_sends_the_payload_to_the_mailbox_path() {
        let gateway = gateway();
        let id = ShortId([2; 8]);
        let (request, _) = client(&gateway, "https://directory.example/")
            .post(id, b"payload")
            .unwrap();

        let (bhttp, _) = receive(&gateway, &request);
        let inner = read_request(&bhttp);
        let control = inner.control();
        assert_eq!(control.method(), Some(&b"POST"[..]));
        assert_eq!(control.path(), Some(format!("/{id}").as_bytes()));
        assert_eq!(inner.content(), b"payload");
    }

    #[test]
    fn requests_are_padded() {
        let gateway = gateway();
        let client = client(&gateway, "https://directory.example/");
        let (get, _) = client.get(ShortId([3; 8])).unwrap();
        let (post, _) = client.post(ShortId([3; 8]), &[0; 7000]).unwrap();
        assert_eq!(get.body.len(), ENCAPSULATED_MESSAGE_BYTES);
        assert_eq!(post.body.len(), ENCAPSULATED_MESSAGE_BYTES);
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let gateway = gateway();
        let result = client(&gateway, "https://directory.example/")
            .post(ShortId([4; 8]), &[0; PADDED_BHTTP_REQUEST_BYTES]);
        assert!(matches!(
            result,
            Err(Error::Ohttp(
                ohttp_client::Error::KnownLengthTooSmall { .. }
            ))
        ));
    }

    #[test]
    fn get_distinguishes_payload_from_timeout() {
        let gateway = gateway();
        let client = client(&gateway, "https://directory.example/");
        let finish = |status, body: &[u8]| {
            let (request, context) = client.get(ShortId([5; 8])).unwrap();
            let (_, response) = receive(&gateway, &request);
            context.finish(&respond(response, status, body))
        };
        assert_eq!(finish(200, b"payload").unwrap(), Some(b"payload".to_vec()));
        assert_eq!(finish(200, b"").unwrap(), Some(Vec::new()));
        assert_eq!(finish(202, b"").unwrap(), None);
    }

    #[test]
    fn post_accepts_ok() {
        let gateway = gateway();
        let (request, context) = client(&gateway, "https://directory.example/")
            .post(ShortId([6; 8]), b"payload")
            .unwrap();
        let (_, response) = receive(&gateway, &request);
        context.finish(&respond(response, 200, b"")).unwrap();
    }

    #[test]
    fn wrong_size_response_is_rejected() {
        let gateway = gateway();
        let client = client(&gateway, "https://directory.example/");
        for size in [
            ENCAPSULATED_MESSAGE_BYTES - 1,
            ENCAPSULATED_MESSAGE_BYTES + 1,
        ] {
            let (_, context) = client.get(ShortId([9; 8])).unwrap();
            assert!(matches!(
                context.finish(&vec![0; size]),
                Err(Error::ResponseSize(s)) if s == size
            ));
        }
    }

    #[test]
    fn unsupported_urls_are_rejected() {
        let gateway = gateway();
        let supported = Url::parse("https://example.com/").unwrap();
        let new = |relay: &Url, directory: &Url| {
            Client::new(
                relay.clone(),
                directory.clone(),
                gateway.config().clone().into(),
            )
            .err()
        };
        for url in [
            "ftp://example.com/",
            "mailto:user@example.com",
            "https://user@example.com/",
            "https://user:password@example.com/",
            "https://example.com/#fragment",
        ] {
            let url = Url::parse(url).unwrap();
            assert_eq!(new(&url, &supported), Some(UnsupportedUrl::Relay), "{url}");
            assert_eq!(
                new(&supported, &url),
                Some(UnsupportedUrl::Directory),
                "{url}"
            );
        }
        assert!(try_client(&gateway, "http://directory.example").is_ok());
    }

    #[test]
    fn statuses_not_defined_by_bip77_are_errors() {
        let gateway = gateway();
        let client = client(&gateway, "https://directory.example/");
        for status in [201, 204, 400, 404, 500] {
            let (request, context) = client.get(ShortId([8; 8])).unwrap();
            let (_, response) = receive(&gateway, &request);
            let result = context.finish(&respond(response, status, b""));
            assert!(
                matches!(result, Err(Error::UnexpectedStatus(s)) if s == status),
                "GET {status}"
            );
        }
        for status in [201, 202, 204, 400, 404, 500] {
            let (request, context) = client.post(ShortId([8; 8]), b"").unwrap();
            let (_, response) = receive(&gateway, &request);
            let result = context.finish(&respond(response, status, b""));
            assert!(
                matches!(result, Err(Error::UnexpectedStatus(s)) if s == status),
                "POST {status}"
            );
        }
    }
}
