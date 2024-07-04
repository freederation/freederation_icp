use bech32::{Hrp};
use crate::signing::{AsymmetricKeyError};

/// `NIP19` error
#[derive(thiserror::Error, Debug)]
pub enum Bech32Error {
    
    #[error("Parse Error: {0}")]
    Parse(crate::util::basecore::ParseError),
        
    #[error("Keys error: {0}")]
    Keys(AsymmetricKeyError),
        
    #[error("EventId error: {0}")]
    EventId(String),    
    
    #[error("Field missing: {0}")]
    FieldMissing(String),    
    
}

impl From<crate::util::basecore::ParseError> for Bech32Error {
    fn from(e:crate::util::basecore::ParseError) -> Self {
        Self::Parse(e)
    }
}
