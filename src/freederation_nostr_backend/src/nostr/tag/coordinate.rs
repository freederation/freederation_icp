use core::fmt;
use core::str::FromStr;
use crate::nostr::event_kind::Kind;
use crate::nostr::event_id::EventId;
use crate::signing::{DataBytes, NostrPubKey};
use serde::{Deserialize, Deserializer, Serialize};
use bech32::{Bech32};
use crate::nostr::event_error::EventDataError;
use crate::util::basecore::ParseError as NParseError;
use crate::util::nostrbech32_params::{
    FromBech32, ToBech32, 
    FIXED_1_1_32_BYTES_TVL ,FIXED_KIND_BYTES_TVL, 
    SPECIAL, RELAY, AUTHOR, KIND, HRP_COORDINATE
};


/// Coordinate for event (`a` tag)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Coordinate {
    /// Kind
    pub kind: Kind,
    /// Public Key
    pub public_key: NostrPubKey,
    /// `d` tag identifier
    ///
    /// Needed for a parametrized replaceable event.
    /// Leave empty for a replaceable event.
    pub identifier: String,
    /// Relays
    pub relays: Vec<String>,
}

impl Coordinate {
    /// Create new event coordinate
    #[inline]
    pub fn new(kind: Kind, public_key: NostrPubKey) -> Self {
        Self {
            kind,
            public_key,
            identifier: String::new(),
            relays: Vec::new(),
        }
    }

    /// Try to parse [Coordinate] from `<kind>:<pubkey>:[<d-tag>]` format, `bech32` or [NIP21](https://github.com/nostr-protocol/nips/blob/master/21.md) uri
    pub fn parse<S>(coordinate: S) -> Result<Self, EventDataError>
    where
        S: AsRef<str>,
    {
        let coordinate: &str = coordinate.as_ref();

        // Try from hex
        if let Ok(coordinate) = Self::from_kpi_format(coordinate) {
            return Ok(coordinate);
        }

        /*
        // Try from bech32
        if let Ok(coordinate) = Self::from_bech32(coordinate) {
            return Ok(coordinate);
        }

        // Try from NIP21 URI
        if let Ok(coordinate) = Self::from_nostr_uri(coordinate) {
            return Ok(coordinate);
        } */

        Err(EventDataError::InvalidCoordinate)
    }

    /// Try to parse from `<kind>:<pubkey>:[<d-tag>]` format
    pub fn from_kpi_format<S>(coordinate: S) -> Result<Self, EventDataError>
    where
        S: AsRef<str>,
    {
        let coordinate: &str = coordinate.as_ref();
        let mut kpi = coordinate.split(':');
        if let (Some(kind_str), Some(public_key_str), Some(identifier)) =
            (kpi.next(), kpi.next(), kpi.next())
        {
            Ok(Self {
                kind: Kind::from_str(kind_str).map_err(|e| EventDataError::Parse(NParseError::ParseInt(e)) )?,
                public_key: NostrPubKey::from_str(public_key_str).map_err(|e| EventDataError::Keys(e) )?,
                identifier: identifier.to_owned(),
                relays: Vec::new(),
            })
        } else {
            Err(EventDataError::InvalidCoordinate)
        }
    }

    /// Set a `d` tag identifier
    ///
    /// Needed for a parametrized replaceable event.
    pub fn identifier<S>(mut self, identifier: S) -> Self
    where
        S: Into<String>,
    {
        self.identifier = identifier.into();
        self
    }

    

}

impl fmt::Display for Coordinate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.kind, self.public_key, self.identifier)
    }
}

impl FromStr for Coordinate {
    type Err = EventDataError;

    /// Try to parse [Coordinate] from `<kind>:<pubkey>:[<d-tag>]` format, `bech32` or [NIP21](https://github.com/nostr-protocol/nips/blob/master/21.md) uri
    #[inline]
    fn from_str(coordinate: &str) -> Result<Self, Self::Err> {
        Self::parse(coordinate)
    }
}


impl FromBech32 for Coordinate
{
    type Err = EventDataError;

    fn from_bech32<S>(bech32str: S) -> Result<Self, Self::Err>
    where
        S: AsRef<str>
    {
        let (hrp, data) = bech32::decode(bech32str.as_ref()).map_err(|e|NParseError::Bech32(e))?;
        if hrp != HRP_COORDINATE {
            return Err(NParseError::WrongBech32PrefixOrVariant.into());
        }
        Self::from_bech32_data(data.as_slice())
    }

    fn from_bech32_data<S>(srcdata: S) -> Result<Self, Self::Err> 
    where
        S: AsRef<[u8]>
    {
        let mut identifier: Option<String> = None;
        let mut pubkey: Option<NostrPubKey> = None;
        let mut kind: Option<Kind> = None;
        let mut relays: Vec<String> = Vec::new();

        let mut data = srcdata.as_ref();

        while !data.is_empty() {
            let t = data.first().ok_or(NParseError::TLV)?;
            let l = data.get(1).ok_or(NParseError::TLV)?;
            let l = *l as usize;

            let bytes: &[u8] = data.get(2..l + 2).ok_or(NParseError::TLV)?;

            match *t {
                SPECIAL => {
                    if identifier.is_none() {
                        identifier = Some(String::from_utf8(bytes.to_vec()).map_err(
                            |e|NParseError::FromUTF8(e)
                        )?);
                    }
                }
                RELAY => {
                    relays.push(String::from_utf8(bytes.to_vec()).map_err(
                        |e| NParseError::FromUTF8(e)
                    )?);
                }
                AUTHOR => {
                    if pubkey.is_none() {
                        pubkey = Some(NostrPubKey::try_from(bytes)?);
                    }
                }
                KIND => {
                    if kind.is_none() {
                        // The kind value must be a 32-bit unsigned number according to
                        // https://github.com/nostr-protocol/nips/blob/37f6cbb775126b386414220f783ca0f5f85e7614/19.md#shareable-identifiers-with-extra-metadata
                        let k: u16 =
                            u32::from_be_bytes(bytes.try_into().map_err(|_| NParseError::TryFromSlice)?)
                                as u16;
                        kind = Some(Kind::from(k));
                    }
                }
                _ => (),
            };

            data = &data[..l + 2];
        }

        Ok(Self {
            kind: kind.ok_or_else(|| NParseError::FieldMissing("kind".to_string()))?,
            public_key: pubkey.ok_or_else(|| NParseError::FieldMissing("pubkey".to_string()))?,
            identifier: identifier.ok_or_else(|| NParseError::FieldMissing("identifier".to_string()))?,
            relays,
        })
    }
}

impl ToBech32 for Coordinate {
    type Err = EventDataError;

    fn to_bech32(&self) -> Result<String, Self::Err> {
        // Allocate capacity
        let identifier_len: usize = 2 + self.identifier.len();
        let relays_len: usize = self.relays.iter().map(|u| 2 + u.len()).sum();
        let mut bytes: Vec<u8> = Vec::with_capacity(
            identifier_len + FIXED_1_1_32_BYTES_TVL + FIXED_KIND_BYTES_TVL + relays_len,
        );

        // Identifier
        bytes.push(SPECIAL); // Type
        bytes.push(self.identifier.len() as u8); // Len
        bytes.extend(self.identifier.as_bytes()); // Value

        // Author
        bytes.push(AUTHOR); // Type
        bytes.push(32); // Len


        let pkeybytes = DataBytes::from(&self.public_key);

        bytes.extend(pkeybytes.as_ref()); // Value

        // Kind
        bytes.push(KIND); // Type
        bytes.push(4); // Len
        bytes.extend(self.kind.as_u32().to_be_bytes()); // Value

        for relay in self.relays.iter() {
            bytes.push(RELAY); // Type
            bytes.push(relay.len() as u8); // Len
            bytes.extend(relay.as_bytes()); // Value
        }

        let bechencode = bech32::encode::<Bech32>(HRP_COORDINATE, &bytes);
        bechencode.map_err(|e| NParseError::ToBech32(e).into())
    }
}

/// Event ID or Coordinate
pub enum EventIdOrCoordinate {
    /// Event ID
    Id(EventId),
    /// Event Coordinate (`a` tag)
    Coordinate(Coordinate),
}

impl From<EventId> for EventIdOrCoordinate {
    fn from(id: EventId) -> Self {
        Self::Id(id)
    }
}

impl From<Coordinate> for EventIdOrCoordinate {
    fn from(coordinate: Coordinate) -> Self {
        Self::Coordinate(coordinate)
    }
}