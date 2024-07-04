
use crate::util::nostrbech32_params::{ToBech32, FromBech32, NostrBech32Prefix};
use crate::util::basecore::{ParseError as NParseError, AsymmetricKeyError};
use crate::signing::{NostrPubKey, NostrSecretKey};
use crate::nostr::event_id::{EventId,DataBytes};
use crate::nostr::tag::relayinfo::RelayUrl;
use crate::nostr::tag::sharedevent::SharedEvent;
use crate::nostr::tag::nostrprofile::NostrProfile;
use crate::nostr::tag::coordinate::Coordinate;
use crate::nostr::event_error::EventDataError;

/// URI scheme
pub const SCHEME: &str = "nostr";

pub type NURIError = EventDataError;



fn split_uri(uri: &str) -> Result<&str, NURIError> {
    let mut splitted = uri.split(':');
    let prefix: &str = splitted.next().ok_or(NParseError::BadURI(uri.to_string()))?;

    if prefix != SCHEME {
        return Err(NParseError::BadURI(uri.to_string()).into());
    }

    splitted.next().ok_or(NParseError::BadURI(uri.to_string()).into())
}



/// Nostr URI trait
pub trait NostrURI: Sized + ToBech32 + FromBech32
where
NURIError: From<<Self as ToBech32>::Err>,
NURIError: From<<Self as FromBech32>::Err>,
{
    /// Get nostr URI
    #[inline]
    fn to_nostr_uri(&self) -> Result<String, NURIError> {
        Ok(format!("{SCHEME}:{}", self.to_bech32()?))
    }

    /// From `nostr` URI
    #[inline]
    fn from_nostr_uri<S>(uri: S) -> Result<Self, NURIError>
    where
        S: AsRef<str>,
    {
        let data: &str = split_uri(uri.as_ref())?;
        Ok(Self::from_bech32(data)?)
    }
}

impl NostrURI for NostrPubKey{}

impl NostrURI for NostrSecretKey{}

impl NostrURI for EventId{}

impl NostrURI for NostrProfile{}

impl NostrURI for Coordinate{}

impl NostrURI for SharedEvent{}

impl NostrURI for RelayUrl{}

/// A representation any `NIP19` bech32 nostr object. Useful for decoding
/// `NIP19` bech32 strings without necessarily knowing what you're decoding
/// ahead of time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NostrTagResource
{
    /// nsec
    Secret(NostrSecretKey),
    /// npub
    Pubkey(NostrPubKey),
    /// nprofile
    Profile(NostrProfile),
    /// note
    EventId(EventId),
    /// nevent
    Event(SharedEvent),
    /// naddr
    Coordinate(Coordinate),
    /// nrelay
    Relay(RelayUrl),
}

impl FromBech32 for NostrTagResource
{
    type Err = NURIError;

    fn from_bech32<S>(bech32: S) -> Result<Self, Self::Err>
    where
        S: AsRef<str>
    {
        let (hrp, data) = bech32::decode(
            bech32.as_ref()).map_err(
                |e|NURIError::Parse(NParseError::Bech32(e))
        )?;

        let prefixhpr = NostrBech32Prefix::from_hrp(&hrp).map_err(|_| NURIError::InvalidResource)?;

        Ok(match prefixhpr {
            NostrBech32Prefix::NSec => 
                NostrTagResource::Secret(
                    NostrSecretKey::from_bech32_data(data.as_slice())?
                ),
            NostrBech32Prefix::NPub => 
                NostrTagResource::Pubkey(
                    NostrPubKey::from_bech32_data(data.as_slice())?
                ),
            NostrBech32Prefix::Note => 
                NostrTagResource::EventId(
                    EventId::from_bech32_data(data.as_slice())?
                ),
            NostrBech32Prefix::NProfile => 
                NostrTagResource::Profile(
                    NostrProfile::from_bech32_data(data.as_slice())?
                ),
            NostrBech32Prefix::NEvent =>
                NostrTagResource::Event(
                    SharedEvent::from_bech32_data(data.as_slice())?
                ),
            NostrBech32Prefix::NAddr => 
                NostrTagResource::Coordinate(
                    Coordinate::from_bech32_data(data.as_slice())?
                ),
            NostrBech32Prefix::NRelay => 
                NostrTagResource::Relay(
                    RelayUrl::from_bech32_data(data.as_slice())?
                ),
        })
    }

    fn from_bech32_data<S>(_srcdata:S) -> Result<Self, Self::Err>
    where
        S: AsRef<[u8]> 
    {
        Err(NURIError::InvalidResource)
    }
}

impl ToBech32 for NostrTagResource
{
    type Err = NURIError;

    fn to_bech32(&self) -> Result<String, Self::Err> {
        match self {
            NostrTagResource::Secret(handle) => handle.to_bech32().map_err(|e| e.into()),
            NostrTagResource::Pubkey(handle) => handle.to_bech32().map_err(|e| e.into()),
            NostrTagResource::Profile(handle) => handle.to_bech32().map_err(|e|e.into()),
            NostrTagResource::EventId(handle) => handle.to_bech32().map_err(|e| e.into()),
            NostrTagResource::Event(handle) => handle.to_bech32().map_err(|e| e.into()),
            NostrTagResource::Coordinate(handle) => handle.to_bech32().map_err(|e| e.into()),
            NostrTagResource::Relay(handle) => handle.to_bech32().map_err(|e| e.into()),
        }
    }
}

impl NostrURI for NostrTagResource{}
