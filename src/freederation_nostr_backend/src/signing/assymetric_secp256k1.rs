
use std::array;

use k256::sha2::{Digest, Sha256};
use hex_conservative::{FromHex, DisplayHex};
use k256::schnorr::signature::{RandomizedSigner, RandomizedDigestSigner, DigestVerifier, Verifier};
use crate::signing::{AsymmetricKeyOps, AsymmetricKeyError, DataField, DataSignature, DataString};

use rand_core::{RngCore};
use crate::rng::CryptoHashRng as CryptoHashRng;
pub use crate::rng::CryptoRngCore;

use crate::util::nostrbech32_params::*;
use bech32::{self, Bech32, Hrp};


pub struct AssymetricSecp256k1();



impl AsymmetricKeyOps for AssymetricSecp256k1
{
    // Generic RNG generator
    type RngGenerator = CryptoHashRng;
        
    type SecretKey = k256::SecretKey;

    type PublicKey = k256::schnorr::VerifyingKey;

    type SigningKey = k256::schnorr::SigningKey;

    type Signature = k256::schnorr::Signature;

    // Instance keypair
    fn new_secret_key_from_bytes(&self, secret_key_bytes: &[u8]) -> Result<Self::SecretKey, AsymmetricKeyError>
    {
        let rk = k256::SecretKey::from_slice(secret_key_bytes);
        match rk {
            Ok(val) => Ok(val),
            Err(e) => Err(AsymmetricKeyError::InvalidSecretKey)
        }
    }

    fn parse_secret_key_from_hex(&self, secret_key_str: &str) -> Result<Self::SecretKey, AsymmetricKeyError>
    {
        match <Vec<u8> as FromHex>::from_hex(secret_key_str) {
            Ok(buffer) => self.new_secret_key_from_bytes(buffer.as_slice()),
            Err(_) => Err(AsymmetricKeyError::InvalidSecretKey)
        }
    }

    fn parse_secret_key_bech32(&self, secret_key_str: &str) -> Result<Self::SecretKey, AsymmetricKeyError>
    {
        let (hrp, data) = bech32::decode(secret_key_str.as_ref()).map_err(|e|AsymmetricKeyError::Bech32Parsing(e))?;
        if hrp != HRP_SECRET_KEY {
            return Err(AsymmetricKeyError::WrongPrefixOrVariant);
        }

        self.new_secret_key_from_bytes(data.as_slice())
    }

    fn generate_secret_key(&self, rngobj: &mut Self::RngGenerator) -> Result<Self::SecretKey, AsymmetricKeyError>
    {
        let mut buffer: DataField = array::from_fn(|_| 0);
        rngobj.fill_bytes(buffer.as_mut_slice());
        self.new_secret_key_from_bytes(buffer.as_slice())
    }
    
    fn secret_key_to_bytes(&self, skey:&Self::SecretKey) -> DataField
    {        
        skey.to_bytes().into()
    }

    fn secret_key_to_hex(&self, skey:&Self::SecretKey) -> DataString
    {
        let buff = skey.to_bytes();
        DisplayHex::to_lower_hex_string( buff.as_slice()).into_boxed_str()
    }

    fn secret_key_to_bech32(&self, skey:&Self::SecretKey) -> DataString
    {
        let buff = self.secret_key_to_bytes(skey);
        let strbuff = bech32::encode::<Bech32>(HRP_SECRET_KEY,buff.as_slice()).unwrap();
        strbuff.into_boxed_str()        
    }


    // Instance keypair
    fn new_public_key_from_bytes(&self, key_bytes: &[u8]) -> Result<Self::PublicKey, AsymmetricKeyError>
    {
        let rk = Self::PublicKey::from_bytes(key_bytes);
        match rk {
            Ok(val) => Ok(val),
            Err(e) => Err(AsymmetricKeyError::InvalidPublicKey)
        }
    }

    fn parse_public_key_from_hex(&self, key_str: &str) -> Result<Self::PublicKey, AsymmetricKeyError>
    {
        match <Vec<u8> as FromHex>::from_hex(key_str) {
            Ok(buffer) => self.new_public_key_from_bytes(buffer.as_slice()),
            Err(_) => Err(AsymmetricKeyError::InvalidPublicKey)
        }
    }

    fn parse_public_key_bech32(&self, key_str: &str) -> Result<Self::PublicKey, AsymmetricKeyError>
    {
        let (hrp, data) = bech32::decode(key_str.as_ref()).map_err(|e|AsymmetricKeyError::Bech32Parsing(e))?;
        if hrp != HRP_PUBLIC_KEY {
            return Err(AsymmetricKeyError::WrongPrefixOrVariant);
        }
        
        self.new_public_key_from_bytes(data.as_slice())
    }
    
    fn public_key_to_bytes(&self, pkey:&Self::PublicKey) -> DataField
    {
        pkey.to_bytes().into()
    }

    fn public_key_to_hex(&self, pkey:&Self::PublicKey) -> DataString
    {
        let buff = pkey.to_bytes();
        DisplayHex::to_lower_hex_string(buff.as_slice()).into_boxed_str()
    }

    fn public_key_to_bech32(&self, pkey:&Self::PublicKey) -> DataString
    {
        let buff = self.public_key_to_bytes(pkey);
        let strbuff = bech32::encode::<Bech32>(HRP_PUBLIC_KEY,buff.as_slice()).unwrap();
        strbuff.into_boxed_str()
    }

    // Instance keypair
    fn new_keypair(&self, secretkey: Self::SecretKey) -> Result<Self::SigningKey, AsymmetricKeyError>
    {
        Ok(k256::schnorr::SigningKey::from(secretkey.clone()))
    }

    fn pubkey_from_pair(&self, signing_key: &Self::SigningKey) -> Self::PublicKey
    {
        signing_key.verifying_key().clone()
    }


    // Instance Signature
    fn new_signature_from_bytes(&self, key_bytes: &[u8]) -> Result<Self::Signature, AsymmetricKeyError>
    {
        let signk = Self::Signature::try_from(key_bytes);
        match signk {
            Ok(kv) => Ok(kv),
            Err(e) => Err(AsymmetricKeyError::ProtocolError(Box::from(e)))
        }
    }

    fn parse_signature_from_hex(&self, key_str: &str) -> Result<Self::Signature, AsymmetricKeyError>
    {
        match <Vec<u8> as FromHex>::from_hex(key_str) {
            Ok(buffer) => self.new_signature_from_bytes(buffer.as_slice()),
            Err(_) => Err(AsymmetricKeyError::SkMissing)
        }
    }

    fn signature_to_bytes(&self, pkey:&Self::Signature) -> DataSignature
    {
        pkey.to_bytes()
    }

    fn signature_to_hex(&self, pkey:&Self::Signature) -> DataString
    {
        let signbytes = pkey.to_bytes();
        DisplayHex::to_lower_hex_string(signbytes.as_slice()).into_boxed_str()
    }
    
    // Signature generation
    fn generate_signature_from_bytes<RG>(&self, msg:&[u8], signer: &Self::SigningKey, rngcore : &mut RG) -> Result<Self::Signature, AsymmetricKeyError>
    where RG: CryptoRngCore
    {
        let rk = signer.try_sign_with_rng(rngcore, msg);
        rk.map_err(|e| AsymmetricKeyError::ProtocolError(Box::new(e)))
    }

    fn generate_signature<RG>(&self, msg:&str, signer: &Self::SigningKey, rngcore : &mut RG) -> Result<Self::Signature, AsymmetricKeyError>
    where RG : CryptoRngCore
    {
        let digest = Sha256::new_with_prefix(msg.as_bytes());
        let rk = signer.try_sign_digest_with_rng(rngcore, digest);
        rk.map_err(|e| AsymmetricKeyError::ProtocolError(Box::new(e)))
    }

    fn verifying_signature_from_bytes(&self, msg:&[u8], pkey:&Self::PublicKey, signature:&Self::Signature) -> Result<(), AsymmetricKeyError>
    {
        let rk = pkey.verify(msg, signature);
        rk.map_err(|e| AsymmetricKeyError::ProtocolError(Box::new(e)))
    }

    fn verifying_signature(&self, msg:&str, pkey:&Self::PublicKey, signature:&Self::Signature) -> Result<(), AsymmetricKeyError>
    {
        let digest = Sha256::new_with_prefix(msg.as_bytes());
        let rk = pkey.verify_digest(digest, signature);
        rk.map_err(|e| AsymmetricKeyError::ProtocolError(Box::new(e)))
    }


}