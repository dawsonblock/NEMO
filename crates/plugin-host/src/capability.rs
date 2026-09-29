// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The capability a session's transports have to present.
//!
//! The credential a host is started with authorises *establishing* a session:
//! the handshake presents it out of band, and the attach presents it again. That
//! is not the same as authorising the operations that follow, which were
//! authorised by naming the session — and a name is not a secret. A peer that
//! can open the socket and learn which session it belongs to could call that
//! session's operations without ever having established it.
//!
//! A capability closes that gap. The kernel mints one per session from the
//! operating system's random source, the host learns it as the session is
//! established, and every later call has to present it. Knowing where the socket
//! is and which session it serves stops being enough, which is the property a
//! boundary between processes is supposed to have.
//!
//! It is not a secret that is written anywhere: it lives in the memory of the
//! two processes that agreed on it, travels only inside the connection neither
//! side hands to anyone else, and is redacted everywhere a value could be
//! printed.

use subtle::ConstantTimeEq;

/// Metadata key carrying the capability on every session-bound request.
pub const SESSION_CAPABILITY_HEADER: &str = "x-nemo-relay-plugin-capability";

/// Random bytes behind one capability.
const CAPABILITY_BYTES: usize = 32;

/// How long a capability is when it is written as lowercase hex.
const CAPABILITY_HEX_LEN: usize = CAPABILITY_BYTES * 2;

/// A session's capability, and the comparison that decides whether a request
/// may be served.
///
/// The comparison is constant-time because the alternative lets a peer recover
/// the capability a byte at a time from how long a refusal takes. The length is
/// not secret — it is the same for every capability this code mints — so only
/// the contents are compared that way.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionCapability(String);

impl SessionCapability {
    /// Mint a capability from the operating system's random source.
    pub fn mint() -> std::io::Result<Self> {
        let mut bytes = [0u8; CAPABILITY_BYTES];
        getrandom::fill(&mut bytes).map_err(std::io::Error::other)?;
        let mut capability = String::with_capacity(CAPABILITY_HEX_LEN);
        for byte in bytes {
            use std::fmt::Write as _;
            // Writing into a String cannot fail, and the formatter cannot fail
            // on a byte.
            let _ = write!(capability, "{byte:02x}");
        }
        Ok(Self(capability))
    }

    /// Read a capability a peer presented, if it is the shape one is.
    ///
    /// A value of the wrong shape is not a capability, so it is refused here
    /// rather than compared: a shorter value than this code mints would be a
    /// weaker capability than the one the session agreed on, and accepting it
    /// would let a peer choose its own strength.
    pub fn parse(presented: Option<&str>) -> Option<Self> {
        let presented = presented?;
        if presented.len() != CAPABILITY_HEX_LEN
            || !presented.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return None;
        }
        Some(Self(presented.to_ascii_lowercase()))
    }

    /// Whether `presented` is this capability.
    pub fn matches(&self, presented: Option<&str>) -> bool {
        match presented {
            Some(presented) if presented.len() == self.0.len() => bool::from(
                self.0
                    .as_bytes()
                    .ct_eq(presented.to_ascii_lowercase().as_bytes()),
            ),
            _ => false,
        }
    }

    /// The capability, for the client that has to present it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The capability is never printed: it is a value that authorises, and a value
/// that authorises in a log line is a value that authorises whoever reads logs.
impl std::fmt::Debug for SessionCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SessionCapability(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minted_capability_is_the_length_the_boundary_expects() {
        let capability = SessionCapability::mint().expect("the operating system's random source");
        assert_eq!(capability.as_str().len(), CAPABILITY_HEX_LEN);
        assert!(
            capability
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
            "a capability travels as hex"
        );
        assert_ne!(
            capability.as_str(),
            SessionCapability::mint().expect("a second draw").as_str(),
            "two sessions do not share a capability"
        );
    }

    #[test]
    fn a_capability_matches_only_itself() {
        let capability = SessionCapability::mint().expect("a capability");
        assert!(capability.matches(Some(capability.as_str())));
        assert!(
            capability.matches(Some(&capability.as_str().to_ascii_uppercase())),
            "hex case is not part of the value"
        );

        let other = SessionCapability::mint().expect("another capability");
        assert!(!capability.matches(Some(other.as_str())));
        assert!(!capability.matches(None), "a request with no capability");

        // A value of the wrong shape is refused rather than compared, so a peer
        // cannot choose a weaker capability than the session agreed on.
        assert!(SessionCapability::parse(Some("")).is_none());
        assert!(SessionCapability::parse(Some("a")).is_none());
        assert!(SessionCapability::parse(Some(&"a".repeat(CAPABILITY_HEX_LEN - 1))).is_none());
        assert!(SessionCapability::parse(Some(&"z".repeat(CAPABILITY_HEX_LEN))).is_none());
        assert!(SessionCapability::parse(Some(&"a".repeat(CAPABILITY_HEX_LEN))).is_some());
    }

    #[test]
    fn a_capability_is_never_printed() {
        let capability = SessionCapability::mint().expect("a capability");
        let secret = capability.as_str().to_owned();
        let printed = format!("{capability:?}");
        assert!(
            !printed.contains(&secret),
            "the debug form redacts the value: {printed}"
        );
        // And the redaction survives being carried in something else that prints
        // its fields, which is how it would reach a log line.
        let holder = vec![capability];
        let printed = format!("{holder:?}");
        assert!(!printed.contains(&secret), "{printed}");
    }
}
