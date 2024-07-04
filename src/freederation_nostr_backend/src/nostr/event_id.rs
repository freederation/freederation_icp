use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};

use crate::signing::{AsymmetricKeyOps, AsymmetricKeyImpl, NostrPubKey};
use crate::util::basecore::ParseError;
use crate::util::time::Timestamp;
use crate::nostr::tag::{TagData, TagError};
use crate::nostr::event_kind::Kind;
use crate::encryption::{Sha256Hash, Sha2Digest,Sha2FixedOutput};
use crate::nostr::event_error::EventIdError;

use core::{str::FromStr};
use core::fmt;

pub use crate::util::basecore::{DataBytes};

use hex_conservative::{FromHex, DisplayHex};
use bech32::{self, Bech32};

use crate::util::nostrbech32_params::{FromBech32, ToBech32};

// Event ID size
pub const EVENT_ID_SIZE: usize = 32;

pub type EventIdHexError = hex_conservative::HexToArrayError;


/// Event ID
///
/// 32-bytes lowercase hex-encoded sha256 of the serialized event data
///
/// <https://github.com/nostr-protocol/nips/blob/master/01.md>
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId([u8; EVENT_ID_SIZE]);

impl EventId {
    /// Generate [`EventId`]
    pub fn new(
        public_key: &NostrPubKey,
        created_at: &Timestamp,
        kind: &Kind,
        tags: &[TagData],
        content: &str,
    ) -> Self {
        let json: Value = json!([0, public_key, created_at, kind, tags, content]);
        let event_str: String = json.to_string();
        let hash: Sha256Hash = Sha256Hash::new_with_prefix(event_str.as_bytes());
        let buff = hash.finalize_fixed();        
        Self::owned(buff.into())
    }

    /// Construct event ID
    #[inline]
    pub fn owned(bytes: [u8; EVENT_ID_SIZE]) -> Self {
        Self(bytes)
    }

    /// Try to parse [EventId] from `hex`, `bech32` or [NIP21](https://github.com/nostr-protocol/nips/blob/master/21.md) uri
    pub fn parse<S>(id: S) -> Result<Self, EventIdError>
    where
        S: AsRef<str>,
    {
        let id: &str = id.as_ref();

        // Try from hex
        if let Ok(id) = Self::from_hex(id) {
            return Ok(id);
        }

        
        // Try from bech32
        if let Ok(id) = Self::from_bech32(id) {
            return Ok(id);
        }
        /*

        // Try from NIP21 URI
        if let Ok(id) = Self::from_nostr_uri(id) {
            return Ok(id);
        } */

        Err(EventIdError::InvalidEventId)
    }

    /// Parse from hex string
    #[inline]
    pub fn from_hex<S>(hex: S) -> Result<Self, EventIdError>
    where S: AsRef<str>,
    {
        match <Vec<u8> as FromHex>::from_hex(hex.as_ref()) {
            Ok(buffer) => {
                Self::from_slice(buffer.as_slice())
            },
            Err(_) => Err(EventIdError::InvalidEventId)
        }
    }

    /// Parse from bytes
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<Self, EventIdError> {
        // Check len
        if slice.len() != EVENT_ID_SIZE {
            return Err(EventIdError::Parse(ParseError::TryFromSlice));
        }

        // Copy bytes
        let mut bytes: [u8; EVENT_ID_SIZE] = [0u8; EVENT_ID_SIZE];
        bytes.copy_from_slice(slice);

        // Construct owned
        Ok(Self::owned(bytes))
    }

    /// All zeros
    #[inline]
    pub fn all_zeros() -> Self {
        Self::owned([0u8; EVENT_ID_SIZE])
    }

    /// Get as bytes
    #[inline]
    pub fn as_bytes(&self) -> &[u8; EVENT_ID_SIZE] {
        &self.0
    }

    /// Consume and get bytes
    #[inline]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Get as hex string
    #[inline]
    pub fn to_hex(&self) -> String {        
        DisplayHex::to_lower_hex_string( self.0.as_slice())
    }

    /// Check POW
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/13.md>
    #[inline]
    pub fn check_pow(&self, difficulty: u8) -> bool {
        crate::util::nostrpow::get_leading_zero_bits(self.as_bytes()) >= difficulty
    }
}




impl FromBech32 for EventId {
    type Err = EventIdError;

    fn from_bech32<S>(hash: S) -> Result<Self, Self::Err>
    where
        S: AsRef<str>,
    {
        let (hrp, data) = bech32::decode(hash.as_ref()).map_err(
            |e|EventIdError::Parse(ParseError::Bech32(e))
        )?;

        if hrp != crate::util::nostrbech32_params::HRP_NOTE_ID {
            return Err(EventIdError::Parse(ParseError::WrongBech32PrefixOrVariant));
        }

        Ok(Self::from_slice(data.as_slice())?)
    }

    fn from_bech32_data<S>(srcdata:S) -> Result<Self, Self::Err>
    where
        S: AsRef<[u8]>
    {
        Self::from_slice(srcdata.as_ref())
    }
}

impl ToBech32 for EventId
{
    type Err = EventIdError;

    fn to_bech32(&self) -> Result<String, Self::Err> {
        let buff : DataBytes = self.as_bytes().clone().into();
        bech32::encode::<Bech32>(
            crate::util::nostrbech32_params::HRP_NOTE_ID,buff.as_ref()
        ).map_err(
            |e| EventIdError::Parse(ParseError::ToBech32(e))
        )
    }
}

impl FromStr for EventId {
    type Err = EventIdError;
            
    #[inline]
    fn from_str(datafield: &str) -> Result<Self, Self::Err> {        
        EventId::from_hex(datafield)
    }
}

// Required to keep clean the methods of `Filter` struct
impl From<&EventId> for String {
    fn from(datafield:&EventId) -> Self {
        datafield.to_hex()
    }
}

impl Serialize for EventId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let strval = self.to_hex();
        serializer.serialize_str(strval.as_str())
    }
}

impl<'de> Deserialize<'de> for EventId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let strdata: String = String::deserialize(deserializer)?;
        EventId::parse(strdata.as_str()).map_err(serde::de::Error::custom)
    }
}


impl From<&EventId> for DataBytes
{
    fn from(value:&EventId) -> Self {        
        let fixedbuff = value.as_bytes();
        fixedbuff.clone().into()
    }
}

impl<Arr> From<Arr> for EventId
where Arr : AsRef<[u8]>
{
    fn from(value: Arr) -> Self {
        EventId::from_slice(value.as_ref()).unwrap()
    }
}

impl fmt::LowerHex for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}
