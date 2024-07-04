use bech32::{Hrp};
use core::str::{self, FromStr};

// Implementation of NIP19
//
// <https://github.com/nostr-protocol/nips/blob/master/19.md>

pub const PREFIX_BECH32_SECRET_KEY: &str = "nsec";
pub const PREFIX_BECH32_PUBLIC_KEY: &str = "npub";
pub const PREFIX_BECH32_NOTE_ID: &str = "note";
pub const PREFIX_BECH32_PROFILE: &str = "nprofile";
pub const PREFIX_BECH32_EVENT: &str = "nevent";
pub const PREFIX_BECH32_COORDINATE: &str = "naddr";
pub const PREFIX_BECH32_RELAY: &str = "nrelay";

pub const HRP_SECRET_KEY: Hrp = Hrp::parse_unchecked(PREFIX_BECH32_SECRET_KEY);
pub const HRP_PUBLIC_KEY: Hrp = Hrp::parse_unchecked(PREFIX_BECH32_PUBLIC_KEY);
pub const HRP_NOTE_ID: Hrp = Hrp::parse_unchecked(PREFIX_BECH32_NOTE_ID);
pub const HRP_PROFILE: Hrp = Hrp::parse_unchecked(PREFIX_BECH32_PROFILE);
pub const HRP_EVENT: Hrp = Hrp::parse_unchecked(PREFIX_BECH32_EVENT);
pub const HRP_COORDINATE: Hrp = Hrp::parse_unchecked(PREFIX_BECH32_COORDINATE);
pub const HRP_RELAY: Hrp = Hrp::parse_unchecked(PREFIX_BECH32_RELAY);

pub const SPECIAL: u8 = 0;
pub const RELAY: u8 = 1;
pub const AUTHOR: u8 = 2;
pub const KIND: u8 = 3;

/// 1 (type) + 1 (len) + 32 (value)
pub(crate) const FIXED_1_1_32_BYTES_TVL: usize = 1 + 1 + 32;

/// 1 (type) + 1 (len) + 4 (value - 32-bit unsigned number)
pub(crate) const FIXED_KIND_BYTES_TVL: usize = 1 + 1 + 4;



/// To ensure total matching on prefixes when decoding a [`Nip19`] object
pub enum NostrBech32Prefix {
    /// Secret Key
    NSec,
    /// Public key
    NPub,
    /// note
    Note,
    /// nprofile
    NProfile,
    /// nevent
    NEvent,
    /// naddr
    NAddr,
    /// nrelay
    NRelay,
}

impl NostrBech32Prefix
{
    pub fn from_hrp(val:&Hrp) -> Result<Self, NostrPrefixBech32Err>
    {
        match val {
            &HPR_SECRET_KEY => Ok(NostrBech32Prefix::NSec),
            &HPR_PUBLIC_KEY => Ok(NostrBech32Prefix::NPub),
            &HPR_NOTE_ID => Ok(NostrBech32Prefix::Note),
            &HPR_PROFILE => Ok(NostrBech32Prefix::NProfile),
            &HPR_EVENT => Ok(NostrBech32Prefix::NEvent),
            &HPR_COORDINATE => Ok(NostrBech32Prefix::NAddr),
            &HPR_RELAY => Ok(NostrBech32Prefix::NRelay),
            _ => Err(NostrPrefixBech32Err::WrongBech32PrefixOrVariant),
        }
    }
}

pub type NostrPrefixBech32Err = crate::util::basecore::ParseError;

impl FromStr for NostrBech32Prefix {
    type Err = NostrPrefixBech32Err;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            PREFIX_BECH32_SECRET_KEY => Ok(NostrBech32Prefix::NSec),
            PREFIX_BECH32_PUBLIC_KEY => Ok(NostrBech32Prefix::NPub),
            PREFIX_BECH32_NOTE_ID => Ok(NostrBech32Prefix::Note),
            PREFIX_BECH32_PROFILE => Ok(NostrBech32Prefix::NProfile),
            PREFIX_BECH32_EVENT => Ok(NostrBech32Prefix::NEvent),
            PREFIX_BECH32_COORDINATE => Ok(NostrBech32Prefix::NAddr),
            PREFIX_BECH32_RELAY => Ok(NostrBech32Prefix::NRelay),
            _ => Err(NostrPrefixBech32Err::WrongBech32PrefixOrVariant),
        }
    }
}


pub trait FromBech32: Sized {
    type Err;
    fn from_bech32<S>(bech32: S) -> Result<Self, Self::Err>
    where
        S: AsRef<str>;
    
    fn from_bech32_data<S>(srcdata:S) -> Result<Self, Self::Err>
    where
        S: AsRef<[u8]>;
}

pub trait ToBech32 {
    type Err;
    fn to_bech32(&self) -> Result<String, Self::Err>;
}

