use crate::signing;
use crate::util::basecore::ParseError;
use crate::nostr::event_error::{EventDataError, EventIdError};


#[derive(thiserror::Error, Debug)]
pub enum TagError {
    
    #[error("Empty Tag")]
    EmptyTag,

    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),
    
    #[error("Keys Error: {0}")]
    Keys(signing::AsymmetricKeyError),

    #[error("Invalid event ID:{0}")]
    InvalidEventId(#[from] EventIdError),

    #[error("Invalid event info: {0}")]
    InvalidEvent(#[from] EventDataError),
    
    #[error("Invalid Image: {0}")]
    Image(#[from] crate::util::nostrimage::Error),

    #[error("Impossible to parse [`Marker`]")]
    MarkerParseError,
    
    #[error("Impossible to find tag kind")]
    KindNotFound,
    
    #[error("Invalid Zap Request")]
    InvalidZapRequest,
    
    #[error("Invalid identity")]
    InvalidIdentity,

    #[error("Invalid Metadata {0}")]
    InvalidMetadata(String),

    #[error("Invalid Relay Metadata {0}")]
    InvalidRelayMetadata(String),

    #[error("Invalid Tag string field {0}")]
    InvalidTagField(String),

    #[error("Unknown standardized tag")]
    UnknownStardardizedTag,
}

