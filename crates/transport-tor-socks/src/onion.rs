//! Onion service addresses.

use tor_hscrypto::pk::{HsId, HsIdParseError};

/// A v3 onion service hostname and a virtual port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addr {
    host: String,
    port: u16,
}

/// The reason a hostname is not a v3 onion address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum InvalidAddr {
    /// The hostname does not end in `.onion`.
    #[error("not an onion hostname")]
    NotOnion,
    /// The part before `.onion` is not 56 base32 characters.
    #[error("malformed onion address")]
    Malformed,
    /// The address encodes a version other than 3.
    #[error("unsupported onion address version {0}")]
    UnsupportedVersion(u8),
    /// The checksum does not match the public key.
    #[error("onion address checksum mismatch")]
    WrongChecksum,
    /// The port is 0, which no onion service can listen on.
    #[error("onion port 0 is unusable")]
    ZeroPort,
}

impl Addr {
    /// Pair a v3 onion hostname with a virtual port. The hostname is kept in
    /// lowercase.
    pub fn new(host: String, port: u16) -> Result<Self, InvalidAddr> {
        let host = host.to_ascii_lowercase();
        let encoded = host.strip_suffix(".onion").ok_or(InvalidAddr::NotOnion)?;
        // `HsId` ignores whatever follows the version byte, so it accepts a
        // longer address.
        if encoded.len() != 56 {
            return Err(InvalidAddr::Malformed);
        }
        host.parse::<HsId>().map_err(invalid_addr)?;
        if port == 0 {
            return Err(InvalidAddr::ZeroPort);
        }
        Ok(Self { host, port })
    }

    /// The `.onion` hostname.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The virtual port on the onion service.
    pub fn port(&self) -> u16 {
        self.port
    }
}

fn invalid_addr(error: HsIdParseError) -> InvalidAddr {
    match error {
        HsIdParseError::NotOnionDomain => InvalidAddr::NotOnion,
        HsIdParseError::UnsupportedVersion(version) => InvalidAddr::UnsupportedVersion(version),
        HsIdParseError::WrongChecksum => InvalidAddr::WrongChecksum,
        _ => InvalidAddr::Malformed,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use data_encoding::BASE32_NOPAD;
    use proptest::prelude::*;
    use safelog::DisplayRedacted;

    use super::*;

    /// The hostname of an onion service with any public key.
    fn onion_host() -> impl Strategy<Value = String> {
        any::<[u8; 32]>().prop_map(|key| HsId::from(key).display_unredacted().to_string())
    }

    /// The public key, checksum and version encoded in a hostname.
    fn decode(host: &str) -> [u8; 35] {
        let encoded = host.strip_suffix(".onion").unwrap().to_ascii_uppercase();
        let bytes = BASE32_NOPAD.decode(encoded.as_bytes()).unwrap();
        bytes.try_into().unwrap()
    }

    /// The hostname that encodes a public key, checksum and version.
    fn encode(bytes: [u8; 35]) -> String {
        format!("{}.onion", BASE32_NOPAD.encode(&bytes).to_ascii_lowercase())
    }

    #[test]
    fn a_hostname_without_the_onion_suffix_is_not_onion() {
        assert_eq!(
            invalid_addr(HsIdParseError::NotOnionDomain),
            InvalidAddr::NotOnion
        );
    }

    #[test]
    fn refuses_port_zero() {
        let host = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";

        assert_eq!(Addr::new(host.to_owned(), 0), Err(InvalidAddr::ZeroPort));
    }

    #[test]
    fn accepts_a_published_address() {
        let host = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";

        assert!(Addr::new(host.to_owned(), 443).is_ok());
    }

    proptest! {
        #[test]
        fn keeps_any_v3_host_and_port(host in onion_host(), port in 1u16..) {
            let addr = Addr::new(host.clone(), port).unwrap();

            prop_assert_eq!(addr.host(), host);
            prop_assert_eq!(addr.port(), port);
        }

        #[test]
        fn keeps_the_host_in_lowercase(host in onion_host()) {
            let addr = Addr::new(host.to_ascii_uppercase(), 1).unwrap();

            prop_assert_eq!(addr.host(), host);
        }

        #[test]
        fn rejects_a_wrong_checksum(host in onion_host(), checksum: [u8; 2]) {
            let mut bytes = decode(&host);
            prop_assume!(checksum != bytes[32..34]);
            bytes[32..34].copy_from_slice(&checksum);

            prop_assert_eq!(Addr::new(encode(bytes), 1), Err(InvalidAddr::WrongChecksum));
        }

        #[test]
        fn rejects_any_other_version(host in onion_host(), version: u8) {
            prop_assume!(version != 3);
            let mut bytes = decode(&host);
            bytes[34] = version;

            prop_assert_eq!(
                Addr::new(encode(bytes), 1),
                Err(InvalidAddr::UnsupportedVersion(version))
            );
        }

        #[test]
        fn rejects_any_other_length(encoded in "[a-z2-7]{0,112}") {
            prop_assume!(encoded.len() != 56);

            prop_assert_eq!(Addr::new(format!("{encoded}.onion"), 1), Err(InvalidAddr::Malformed));
        }

        #[test]
        fn rejects_characters_after_a_valid_address(host in onion_host(), extra in "[a-z2-7]{1,16}") {
            let encoded = host.strip_suffix(".onion").unwrap();

            prop_assert_eq!(
                Addr::new(format!("{encoded}{extra}.onion"), 1),
                Err(InvalidAddr::Malformed)
            );
        }

        #[test]
        fn rejects_a_character_outside_base32_anywhere(
            host in onion_host(),
            at in 0usize..56,
            outside in "[0189_.=-]",
        ) {
            let mut host = host;
            host.replace_range(at..=at, &outside);

            prop_assert_eq!(Addr::new(host, 1), Err(InvalidAddr::Malformed));
        }

        #[test]
        fn rejects_any_other_suffix(host in onion_host(), suffix in "(\\.[a-z]{1,8})?") {
            prop_assume!(suffix != ".onion");
            let encoded = host.strip_suffix(".onion").unwrap();

            prop_assert_eq!(Addr::new(format!("{encoded}{suffix}"), 1), Err(InvalidAddr::NotOnion));
        }
    }
}
