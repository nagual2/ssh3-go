//! Extensions for the HTTP/3 protocol.

use std::{borrow::Cow, convert::Infallible, str::FromStr};

/// Describes the `:protocol` pseudo-header for extended connect
///
/// See: <https://www.rfc-editor.org/rfc/rfc8441#section-4>
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Protocol(Cow<'static, str>);

impl Protocol {
    /// WebTransport protocol
    pub const WEB_TRANSPORT: Protocol = Protocol(Cow::Borrowed("webtransport"));
    /// RFC 9298 protocol
    pub const CONNECT_UDP: Protocol = Protocol(Cow::Borrowed("connect-udp"));

    /// Create a protocol token from a static or owned string.
    #[inline]
    pub fn new(value: impl Into<Cow<'static, str>>) -> Self {
        Self(value.into())
    }

    /// Return a &str representation of the `:protocol` pseudo-header value
    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

/// Error when parsing the protocol
pub struct InvalidProtocol;

impl FromStr for Protocol {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s.to_owned()))
    }
}
