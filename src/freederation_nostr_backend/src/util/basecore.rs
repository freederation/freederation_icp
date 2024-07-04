use serde::{Deserialize, Deserializer, Serialize};
use core::num::ParseIntError;
use std::string::{FromUtf8Error, String, ToString};
use core::str::{self, FromStr, Utf8Error};


pub const FIELD_BYTE_SIZE:usize = 32;
pub const SIGNATURE_BYTE_SIZE:usize = 64;

pub type DataField = [u8;FIELD_BYTE_SIZE];
pub type DataSignature = [u8;SIGNATURE_BYTE_SIZE];

pub type DataString = Box<str>;

pub type DataBytes = Box<[u8]>;


trait_set::trait_set!{pub trait HexFieldParse =  hex_conservative::FromHex}

pub type HexFieldError = hex_conservative::HexToArrayError;
pub type HexBytesdError = hex_conservative::HexToBytesError;

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    
    #[error("Hex Field decode error: {0}")]
    Hex(#[from] HexFieldError),

    #[error("Hex Data decode error: {0}")]
    HexData(#[from] HexBytesdError),
    
    #[error("Parse Int: {0}")]
    ParseInt(#[from] ParseIntError),

    #[error("Invalid URL: {0}")]
    URL(#[from] url::ParseError),

    #[error("Undefined URI Resource: {0}")]
    BadURI(String),
    
    #[error("Utf8 decoding error: {0}")]
    FromUTF8(#[from] FromUtf8Error),
    
    #[error("Utf8 encoding error: {0}")]
    UTF8(#[from] Utf8Error),


    #[error("Fmt error: {0}")]
    Fmt(#[from] core::fmt::Error),
    

    #[error("Bech32 decoding error: {0}")]
    Bech32(#[from] bech32::DecodeError),

    #[error("Bech32 encoding error: {0}")]
    ToBech32(#[from] bech32::EncodeError),

    #[error("Wrong Bech32 prefix or variant")]
    WrongBech32PrefixOrVariant,    

    #[error("TLV (type-length-value) error")]
    TLV,

    #[error("Field is missing: {0}")]
    FieldMissing(String),
    
    #[error("Impossible to perform conversion from slice")]
    TryFromSlice,

    #[error("Deserialization Error:{0}")]
    Deserialization(String),

    #[error("From JSON Error:{0}")]
    FromJSON(#[from] serde_json::Error)
}


// keys error
#[derive(thiserror::Error, Debug)]
pub enum AsymmetricKeyError {
    /// Invalid secret key
    #[error("Invalid secret key")]
    InvalidSecretKey,
    /// Invalid public key
    #[error("Invalid public key")]
    InvalidPublicKey,
    
    #[error("Secret key missing")]
    SkMissing,
    
    #[error("Bad Hex Format")]
    HexParsing,

    /// Secret key missing
    #[error("Bad Bech32 Format")]
    Bech32Parsing(#[from] bech32::DecodeError),

    #[error("Bech32 encoding error: {0}")]
    ToBech32(#[from] bech32::EncodeError),

    /// Unsupported char
    #[error("Unsupported char: {0}")]
    InvalidChar(char),

    #[error("Bad Bech32 Prefix")]
    WrongPrefixOrVariant,

    /// Protocol error
    #[error("Encryption Protocol Error {0}")]
    ProtocolError(Box<dyn std::error::Error>),
}
