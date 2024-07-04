use k256::sha2::{Sha256};
pub use k256::sha2::Digest as Sha2Digest;
pub use k256::sha2::digest::FixedOutput as Sha2FixedOutput;

use k256::sha2::digest::{Output};


use hex_conservative::{FromHex, HexToBytesError};


pub type Sha256Hash = Sha256;
pub type Sha256ParseError = HexToBytesError;
pub type Sha256HashArray = Output<Sha256Hash>;


pub fn sha256_from_hex(hexstr:&str) -> Result<Sha256Hash, Sha256ParseError>
{
    let bytesbuffer: Vec<u8> = FromHex::from_hex(hexstr)?;
    Ok(Sha256Hash::new_with_prefix(bytesbuffer.as_slice()))
}