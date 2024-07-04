use crate::signing;
use crate::util::basecore::ParseError;

/// [`EventId`] error
#[derive(thiserror::Error, Debug)]
pub enum EventIdError {
    
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),
    
    #[error("Invalid event ID")]
    InvalidEventId,
}


#[derive(thiserror::Error, Debug)]
pub enum EventDataError {
    
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),
    
    #[error("Invalid event ID:{0}")]
    InvalidEventId(#[from] EventIdError),

    #[error("Keys Error: {0}")]
    Keys(#[from] signing::AsymmetricKeyError),        
    
    #[error("Invalid coordinate")]
    InvalidCoordinate,

    #[error("Invalid Resource")]
    InvalidResource,

    #[error("Event Hash Validation Error")]
    InvalidEventHash,

    #[error("Event Signature Validation Error")]
    InvalidEventSignature(signing::AsymmetricKeyError),

    #[error("Event Pow Validation Error, dificulty {0}")]
    InvalidEventIdPow(u8),
}

