use core::fmt;
use core::str::{FromStr};
use url::Url;
use std::string::{FromUtf8Error, String, ToString};
use serde::{Deserialize, Deserializer, Serialize};
use bech32::{Bech32};
use crate::util::basecore::ParseError as NParseError;
use crate::util::nostrbech32_params::{
    FromBech32, ToBech32, SPECIAL, HRP_RELAY
};


/// A Url validated as a nostr relay url in canonical form
/// We don't serialize/deserialize these directly, see `UncheckedUrl` for that
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RelayUrl{
    url:Url
}

impl RelayUrl {
    
    pub fn new(url: Url) -> Self {
        Self { url }
    }
    
}


impl From<RelayUrl> for Url {
    fn from(ru: RelayUrl) -> Url {
        ru.url
    }
}

impl ToBech32 for RelayUrl {
    type Err = NParseError;

    fn to_bech32(&self) -> Result<String, Self::Err> {
        let url: &[u8] = self.url.as_str().as_bytes();

        // Allocate capacity
        let mut bytes: Vec<u8> = Vec::with_capacity(1 + 1 + url.len());

        bytes.push(SPECIAL); // Type
        bytes.push(url.len() as u8); // Len
        bytes.extend(url); // Value

        Ok(bech32::encode::<Bech32>(HRP_RELAY, &bytes)?)
    }
}

impl FromBech32 for RelayUrl {
    type Err = NParseError;

    fn from_bech32<S>(s: S) -> Result<Self, Self::Err>
    where
        S: AsRef<str>,
    {
        let (hrp, data) = bech32::decode(s.as_ref())?;

        if hrp != HRP_RELAY {
            return Err(NParseError::WrongBech32PrefixOrVariant);
        }

        Self::from_bech32_data(data.as_slice())
    }

    fn from_bech32_data<S>(srcdata:S) -> Result<Self, Self::Err> 
    where
        S: AsRef<[u8]>,
    {
        let mut url: Option<Url> = None;
        let mut data = srcdata.as_ref();

        while !data.is_empty() {
            let t = data.first().ok_or(NParseError::TLV)?;
            let l = data.get(1).ok_or(NParseError::TLV)?;
            let l = *l as usize;

            let bytes = data.get(2..l + 2).ok_or(NParseError::TLV)?;

            if *t == SPECIAL && url.is_none() {
                let u: &str = core::str::from_utf8(bytes).map_err(
                    |e|NParseError::UTF8(e)
                )?;
                url = Some(Url::from_str(u).map_err(|e|NParseError::URL(e)) ?);
            }

            data = &data[..l + 2];
        }

        Ok(Self {
            url: url.ok_or_else(|| NParseError::FieldMissing("url".to_string()))?,
        })
    }
}