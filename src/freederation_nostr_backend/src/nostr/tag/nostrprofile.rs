use url::{Url};
use crate::signing::{DataBytes, NostrPubKey};
use serde::{Deserialize, Serialize};
use bech32::{Bech32};
use crate::util::basecore::ParseError as NParseError;
use crate::util::uncheckedurl::TryIntoUrl;
use crate::util::nostrbech32_params::{
    FromBech32, ToBech32, 
    FIXED_1_1_32_BYTES_TVL ,HRP_PROFILE, 
    SPECIAL, RELAY
};


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NostrProfile {
    pub public_key: NostrPubKey,
    pub relays: Vec<Url>,
}

impl NostrProfile {
    #[inline]
    pub fn new<I, U>(public_key: NostrPubKey, relays: I) -> Result<Self, NParseError>
    where
        I: IntoIterator<Item = U>,
        U: TryIntoUrl,
        NParseError: From<<U as TryIntoUrl>::Err>,
    {
        Ok(Self {
            public_key,
            relays: relays
                .into_iter()
                .map(|u| u.try_into_url())
                .collect::<Result<Vec<Url>, _>>()?,
        })
    }

    
}

impl ToBech32 for NostrProfile {
    type Err = NParseError;

    fn to_bech32(&self) -> Result<String, Self::Err> {
        // Allocate capacity
        let relays_len: usize = self.relays.iter().map(|u| 2 + u.as_str().len()).sum();
        let mut bytes: Vec<u8> = Vec::with_capacity(FIXED_1_1_32_BYTES_TVL + relays_len);

        bytes.push(SPECIAL); // Type
        bytes.push(32); // Len
        let keybytes = DataBytes::from(&self.public_key);
        bytes.extend(keybytes.as_ref()); // Value

        for relay in self.relays.iter() {
            let url: &[u8] = relay.as_str().as_bytes();
            bytes.push(RELAY); // Type
            bytes.push(url.len() as u8); // Len
            bytes.extend(url); // Value
        }

        Ok(bech32::encode::<Bech32>(HRP_PROFILE, &bytes)?)
    }
}

impl FromBech32 for NostrProfile {
    type Err = NParseError;

    fn from_bech32<S>(s: S) -> Result<Self, Self::Err>
    where
        S: AsRef<str>,
    {
        let (hrp, data) = bech32::decode(s.as_ref())?;

        if hrp != HRP_PROFILE {
            return Err(NParseError::WrongBech32PrefixOrVariant);
        }

        Self::from_bech32_data(data.as_slice())
    }

    fn from_bech32_data<S>(srcdata: S) -> Result<Self, Self::Err>
    where
        S: AsRef<[u8]>,
    {
        let mut public_key: Option<NostrPubKey> = None;
        let mut relays: Vec<Url> = Vec::new();

        let mut data = srcdata.as_ref();

        while !data.is_empty() {
            let t = data.first().ok_or(NParseError::TLV)?;
            let l = data.get(1).ok_or(NParseError::TLV)?;
            let l = *l as usize;

            let bytes = data.get(2..l + 2).ok_or(NParseError::TLV)?;

            match *t {
                SPECIAL => {
                    if public_key.is_none() {
                        let rkey = NostrPubKey::try_from(bytes).map_err(
                            |e| NParseError::TryFromSlice 
                        )?;
                        public_key = Some(rkey);
                    }
                }
                RELAY => {
                    let url = String::from_utf8(bytes.to_vec())?;
                    let url = Url::parse(&url)?;
                    relays.push(url);
                }
                _ => (),
            };

            data = &data[..l + 2];
        }

        Ok(Self {
            public_key: public_key.ok_or_else(|| NParseError::FieldMissing("pubkey".to_string()))?,
            relays,
        })
    }
}