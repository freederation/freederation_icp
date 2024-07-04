use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use rand_core::{CryptoRng, RngCore};

pub type CryptoHashRng = ChaCha20Rng;
pub type CryptoHashSeed = <ChaCha20Rng as SeedableRng>::Seed;

trait_set::trait_set!{pub trait CryptoRngCore =  CryptoRng + RngCore}