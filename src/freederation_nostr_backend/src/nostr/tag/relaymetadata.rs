//! NIP65
//!
//! <https://github.com/nostr-protocol/nips/blob/master/65.md>

use std::string::{String, ToString};
use core::fmt;
use core::str::FromStr;


/// NIP-56 error
#[derive(thiserror::Error, Debug)]
pub enum RelayMetaError {
    #[error("Invalid Relay Metadata:{0}")]
    InvalidRelayMetadata(String),
}


/// Relay Metadata
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelayMetadata {
    /// Read
    Read,
    /// Write
    Write,
}

impl fmt::Display for RelayMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => write!(f, "read"),
            Self::Write => write!(f, "write"),
        }
    }
}

impl FromStr for RelayMetadata {
    type Err = RelayMetaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            s => Err(RelayMetaError::InvalidRelayMetadata(s.to_string())),
        }
    }
}

/*
#[inline]
pub fn extract_relay_list(event: &Event) -> Vec<(&Url, &Option<RelayMetadata>)> {
    event
        .iter_tags()
        .filter_map(|tag| {
            if let Some(TagStandard::RelayMetadata {
                relay_url,
                metadata,
            }) = tag.as_standardized()
            {
                Some((relay_url, metadata))
            } else {
                None
            }
        })
        .collect()
}
 */