use core::fmt;
use core::str::{FromStr};
use url::Url;
use std::string::{FromUtf8Error, String, ToString};
use serde::{Deserialize, Deserializer, Serialize};
use bech32::{Bech32};
use crate::nostr::event_id::EventId;
use crate::signing::{DataBytes, NostrPubKey};
use crate::nostr::event_kind::Kind;
use crate::util::basecore::ParseError as NParseError;
use crate::util::nostrbech32_params::{
    FromBech32, ToBech32, SPECIAL, HRP_EVENT, FIXED_1_1_32_BYTES_TVL, AUTHOR, KIND, RELAY
};

/// A Nostr shareable `nevent` that includes author and relay data. Used from tags
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SharedEvent {
    pub event_id: EventId,
    pub author: Option<NostrPubKey>,
    pub kind: Option<Kind>,
    pub relays: Vec<String>,
}

impl SharedEvent {
    #[inline]
    pub fn new<I, S>(event_id: EventId, relays: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            event_id,
            author: None,
            kind: None,
            relays: relays.into_iter().map(|u| u.into()).collect(),
        }
    }

    /// Add author
    #[inline]
    pub fn author(mut self, author: NostrPubKey) -> Self {
        self.author = Some(author);
        self
    }

    /// Add kind
    #[inline]
    pub fn kind(mut self, kind: Kind) -> Self {
        self.kind = Some(kind);
        self
    }

    
}

impl FromBech32 for SharedEvent {
    type Err = NParseError;

    fn from_bech32<S>(s: S) -> Result<Self, Self::Err>
    where
        S: AsRef<str>,
    {
        let (hrp, data) = bech32::decode(s.as_ref())?;

        if hrp != HRP_EVENT {
            return Err(NParseError::WrongBech32PrefixOrVariant);
        }

        Self::from_bech32_data(data.as_slice())
    }

    fn from_bech32_data<S>(srcdata:S) -> Result<Self, Self::Err>
    where
        S: AsRef<[u8]>,
    {
        let mut event_id: Option<EventId> = None;
        let mut author: Option<NostrPubKey> = None;
        let mut kind: Option<Kind> = None;
        let mut relays: Vec<String> = Vec::new();

        let mut data = srcdata.as_ref();

        while !data.is_empty() {
            let t = data.first().ok_or(NParseError::TLV)?;
            let l = data.get(1).ok_or(NParseError::TLV)?;
            let l = *l as usize;

            let bytes = data.get(2..l + 2).ok_or(NParseError::TLV)?;

            match *t {
                SPECIAL => {
                    if event_id.is_none() {
                        event_id = Some(EventId::from_slice(bytes).map_err(|e| NParseError::TryFromSlice)?);
                    }
                }
                // from nip19: "for nevent, *optionally*, the 32 bytes of
                // the pubkey of the event"
                AUTHOR => {
                    if author.is_none() {
                        author = NostrPubKey::try_from(bytes).ok(); // NOT propagate error if public key is invalid
                    }
                }
                RELAY => {
                    relays.push(String::from_utf8(bytes.to_vec())?);
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
            event_id: event_id.ok_or_else(|| NParseError::FieldMissing("event id".to_string()))?,
            author,
            kind,
            relays,
        })
    }
}

impl ToBech32 for SharedEvent {
    type Err = NParseError;

    fn to_bech32(&self) -> Result<String, Self::Err> {
        // Allocate capacity
        let relays_len: usize = self.relays.iter().map(|u| 2 + u.len()).sum();
        let author_len: usize = if self.author.is_some() {
            FIXED_1_1_32_BYTES_TVL
        } else {
            0
        };
        let mut bytes: Vec<u8> =
            Vec::with_capacity(FIXED_1_1_32_BYTES_TVL + author_len + relays_len);

        bytes.push(SPECIAL); // Type
        bytes.push(32); // Len
        bytes.extend(self.event_id.as_bytes()); // Value

        if let Some(author) = &self.author {
            bytes.push(AUTHOR); // Type
            bytes.push(32); // Len
            let authbytes = DataBytes::from(author);
            bytes.extend(authbytes.as_ref()); // Value
        }

        if let Some(kind) = &self.kind {
            bytes.push(KIND); // Type
            bytes.push(4); // Len
            bytes.extend(kind.as_u32().to_be_bytes()); // Value
        }

        for relay in self.relays.iter() {
            bytes.push(RELAY); // Type
            bytes.push(relay.len() as u8); // Len
            bytes.extend(relay.as_bytes()); // Value
        }

        Ok(bech32::encode::<Bech32>(HRP_EVENT, &bytes)?)
    }
}