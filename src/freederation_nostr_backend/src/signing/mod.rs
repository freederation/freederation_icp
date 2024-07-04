use core::{str::FromStr};
use core::fmt;
use serde::{Deserialize, Deserializer, Serialize};
use std::hash::{DefaultHasher, Hash, Hasher};
use core::convert::TryFrom;

pub use crate::util::basecore::{DataField, DataSignature, DataString, DataBytes, AsymmetricKeyError};

pub use crate::rng::CryptoRngCore;


pub trait AsymmetricKeyOps
{
    // Generic RNG generator
    type RngGenerator : CryptoRngCore;
        
    type SecretKey;

    type PublicKey;

    type SigningKey;

    type Signature;

    // Instance keypair
    fn new_secret_key_from_bytes(&self, secret_key_bytes: &[u8]) -> Result<Self::SecretKey, AsymmetricKeyError>;

    fn parse_secret_key_from_hex(&self, secret_key_str: &str) -> Result<Self::SecretKey, AsymmetricKeyError>;

    fn parse_secret_key_bech32(&self, secret_key_str: &str) -> Result<Self::SecretKey, AsymmetricKeyError>;

    fn generate_secret_key(&self, rngobj: &mut Self::RngGenerator) -> Result<Self::SecretKey, AsymmetricKeyError>;

    /// Try to parse from **secret key** `hex` or `bech32`
    fn parse_secret_key(&self, secret_key_str: &str) -> Result<Self::SecretKey, AsymmetricKeyError>
    {
        if let Ok(sk) = self.parse_secret_key_from_hex(secret_key_str) {
            Ok(sk)
        }
        else { 
            self.parse_secret_key_bech32(secret_key_str) 
        }
    }

    fn secret_key_to_bytes(&self, skey:&Self::SecretKey) -> DataField;

    fn secret_key_to_hex(&self, skey:&Self::SecretKey) -> DataString;

    fn secret_key_to_bech32(&self, skey:&Self::SecretKey) -> DataString;


    // Instance keypair
    fn new_public_key_from_bytes(&self, key_bytes: &[u8]) -> Result<Self::PublicKey, AsymmetricKeyError>;

    fn parse_public_key_from_hex(&self, key_str: &str) -> Result<Self::PublicKey, AsymmetricKeyError>;

    fn parse_public_key_bech32(&self, key_str: &str) -> Result<Self::PublicKey, AsymmetricKeyError>;

    /// Try to parse from **key** `hex` or `bech32`
    fn parse_public_key(&self, key_str: &str) -> Result<Self::PublicKey, AsymmetricKeyError>
    {
        if let Ok(sk) = self.parse_public_key_from_hex(key_str) {
            Ok(sk)
        }
        else { 
            self.parse_public_key_bech32(key_str) 
        }
    }


    fn public_key_to_bytes(&self, pkey:&Self::PublicKey) -> DataField;

    fn public_key_to_hex(&self, pkey:&Self::PublicKey) -> DataString;

    fn public_key_to_bech32(&self, pkey:&Self::PublicKey) -> DataString;

    // Instance keypair
    fn new_keypair(&self, secretkey: Self::SecretKey) -> Result<Self::SigningKey, AsymmetricKeyError>;

    fn generate_keypair(&self, rngobj: &mut Self::RngGenerator) -> Result<Self::SigningKey, AsymmetricKeyError>
    {
        let sk = self.generate_secret_key(rngobj)?;
        self.new_keypair(sk)
    }

    fn pubkey_from_pair(&self, signing_key: &Self::SigningKey) -> Self::PublicKey;

    // Instance Signature
    fn new_signature_from_bytes(&self, key_bytes: &[u8]) -> Result<Self::Signature, AsymmetricKeyError>;

    fn parse_signature_from_hex(&self, key_str: &str) -> Result<Self::Signature, AsymmetricKeyError>;

    
    /// Try to parse from **key** `hex` or `bech32`
    fn parse_signature(&self, key_str: &str) -> Result<Self::Signature, AsymmetricKeyError>
    {
        self.parse_signature_from_hex(key_str)
    }


    fn signature_to_bytes(&self, pkey:&Self::Signature) -> DataSignature;

    fn signature_to_hex(&self, pkey:&Self::Signature) -> DataString;
    

    // Signature generation
    fn generate_signature_from_bytes<RG>(&self, msg:&[u8], signer: &Self::SigningKey, rngcore : &mut RG) -> Result<Self::Signature, AsymmetricKeyError>
    where RG : CryptoRngCore;

    fn generate_signature<RG>(&self, msg:&str, signer: &Self::SigningKey, rngcore : &mut RG) -> Result<Self::Signature, AsymmetricKeyError>
    where RG : CryptoRngCore;

    fn verifying_signature_from_bytes(&self, msg:&[u8], pkey:&Self::PublicKey, signature:&Self::Signature) -> Result<(), AsymmetricKeyError>;

    fn verifying_signature(&self, msg:&str, pkey:&Self::PublicKey, signature:&Self::Signature) -> Result<(), AsymmetricKeyError>;


}

mod assymetric_secp256k1;

pub use assymetric_secp256k1::AssymetricSecp256k1 as AsymmetricKeyImpl;

#[derive(Debug, Clone)]
pub struct NostrPubKey(pub <AsymmetricKeyImpl as AsymmetricKeyOps>::PublicKey);

#[derive(Debug, Clone)]
pub struct NostrSecretKey(pub <AsymmetricKeyImpl as AsymmetricKeyOps>::SecretKey);

#[derive(Debug, Clone)]
pub struct NostrSignature(pub <AsymmetricKeyImpl as AsymmetricKeyOps>::Signature);


macro_rules! nostr_key_ser {
    ($type:ident, $parse_fn:ident, $hexstr_fn:ident, $frombytes_fn:ident, $tobytes_fn:ident) => {

        impl FromStr for $type {
            type Err = AsymmetricKeyError;
                    
            #[inline]
            fn from_str(datafield: &str) -> Result<Self, Self::Err> {
                let ecda = AsymmetricKeyImpl();
                ecda.$parse_fn(datafield).map($type)
            }
        }
        
        // Required to keep clean the methods of `Filter` struct
        impl From<& $type> for String {
            fn from(datafield: & $type) -> Self {
                let ecda = AsymmetricKeyImpl();
                ecda.$hexstr_fn(&datafield.0).into_string()
            }
        }
        
        impl fmt::Display for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.to_string())
            }
        }

        impl Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let ecda = AsymmetricKeyImpl();
                serializer.serialize_str(ecda.$hexstr_fn(&self.0).as_ref())
            }
        }

        
        
        
        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let strdata: String = String::deserialize(deserializer)?;
                let ecda = AsymmetricKeyImpl();
                ecda.$parse_fn(strdata.as_str()).map($type).map_err(serde::de::Error::custom)
            }
        }


        impl From<& $type> for DataBytes
        {
            fn from(value:& $type) -> Self {
                let ecda = AsymmetricKeyImpl();
                let fixedbuff = ecda.$tobytes_fn(&value.0);
                fixedbuff.into()
            }
        }

        impl TryFrom<&[u8]> for $type
        {
            type Error = AsymmetricKeyError;

            fn try_from(value:&[u8]) -> Result<Self, Self::Error> {
                let ecda = AsymmetricKeyImpl();
                let pkey = ecda.$frombytes_fn(value.as_ref());
                pkey.map(|v| $type(v))
            }
        }

        impl PartialEq for $type
        {
            fn eq(&self, other: &Self) -> bool {
                let ecda = AsymmetricKeyImpl();
                let selfbytes = ecda.$tobytes_fn(&self.0);
                let otherbytes = ecda.$tobytes_fn(&other.0);
                selfbytes.eq(&otherbytes)
            }
        }

        impl PartialOrd for $type
        {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                let ecda = AsymmetricKeyImpl();
                let selfbytes = ecda.$tobytes_fn(&self.0);
                let otherbytes = ecda.$tobytes_fn(&other.0);
                selfbytes.partial_cmp(&otherbytes)
            }
        }


        impl Eq for $type
        {    
        }

        impl Ord for $type
        {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.partial_cmp(other).unwrap_or(std::cmp::Ordering::Less)
            }
        }

        impl Hash for $type{
            fn hash<H: Hasher>(&self, state: &mut H) {
                let ecda = AsymmetricKeyImpl();        
                let selfbytes = ecda.$tobytes_fn(&self.0);
                selfbytes.hash(state);
            }
        }

    };
}

nostr_key_ser!(NostrPubKey,parse_public_key, public_key_to_hex, new_public_key_from_bytes, public_key_to_bytes);

nostr_key_ser!(NostrSecretKey,parse_secret_key, secret_key_to_hex, new_secret_key_from_bytes, secret_key_to_bytes);

nostr_key_ser!(NostrSignature,parse_signature, signature_to_hex, new_signature_from_bytes, signature_to_bytes);


use crate::util::nostrbech32_params::{FromBech32, ToBech32};
use bech32::{Bech32};
use crate::util::nostrbech32_params::HRP_PUBLIC_KEY as NOSTR_HPR_PUBLIC_KEY;

use crate::util::nostrbech32_params::HRP_SECRET_KEY as NOSTR_HRP_SECRET_KEY;

macro_rules! nostr_key_bech32ser {
    ($type:ident, $hprkey:ident) => {

        impl FromBech32 for $type
        {
            type Err = AsymmetricKeyError;

            fn from_bech32<S>(bech32str: S) -> Result<Self, Self::Err>
            where
                S: AsRef<str>
            {
                let (hrp, data) = bech32::decode(bech32str.as_ref()).map_err(|e|AsymmetricKeyError::Bech32Parsing(e))?;
                if hrp != $hprkey {
                    return Err(AsymmetricKeyError::WrongPrefixOrVariant);
                }

                $type::try_from(data.as_slice())
            }

            fn from_bech32_data<S>(srcdata:S) -> Result<Self, Self::Err>
            where
                S: AsRef<[u8]>,
            {
                $type::try_from(srcdata.as_ref())
            }
        }

        impl ToBech32 for $type
        {
            type Err = AsymmetricKeyError;

            fn to_bech32(&self) -> Result<String, Self::Err> {                
                let buff : DataBytes = self.into();        
                bech32::encode::<Bech32>($hprkey,buff.as_ref()).map_err(|e|AsymmetricKeyError::ToBech32(e))
            }
        }

    };
}


nostr_key_bech32ser!(NostrPubKey, NOSTR_HPR_PUBLIC_KEY);

nostr_key_bech32ser!(NostrSecretKey, NOSTR_HRP_SECRET_KEY);
