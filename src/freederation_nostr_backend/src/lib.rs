use rng::CryptoHashRng;
use signing::AsymmetricKeyOps;
use hex_conservative::{DisplayHex, FromHex};
use candid::{CandidType,  Deserialize};
use std::{borrow::Borrow, cell::RefCell};
use rand_core::{CryptoRng,SeedableRng, RngCore};


mod signing;
mod encryption;
mod rng;
mod util;
mod nostr;

#[derive(CandidType, Deserialize)]
struct RNG_SEED {
    inner: crate::rng::CryptoHashSeed
}

impl RNG_SEED
{
    fn new_seed() ->Self {
        let seed = crate::rng::CryptoHashSeed::default();
        Self{inner:seed}
    }

    fn assign_bytes(&mut self, buffer:&[u8])
    {
        let target_len = self.inner.len();
        let lendiff = target_len.min(buffer.len());
        self.inner[0..lendiff].copy_from_slice(&buffer[0..lendiff]);
        if lendiff < target_len {
            self.inner[lendiff..].fill(0);
        }
    }
}


/// Signature Info
#[derive(CandidType, Deserialize)]
struct SIGNATURE_INFO {
    signature_str: String,
    verifying_key: String
}

thread_local! {
    static GLOBAL_RNG_SEED: RefCell<RNG_SEED> = RefCell::new(RNG_SEED::new_seed());
}

#[ic_cdk::query]
fn rng_seed() -> String {
    GLOBAL_RNG_SEED.with(|rngseed| rngseed.borrow().inner.to_lower_hex_string())
}

#[ic_cdk::update]
fn update_rng_seed(val:String) {
    GLOBAL_RNG_SEED.with_borrow_mut(|rngseed| {
        let buffer = <Vec<u8> as FromHex >::from_hex(val.as_str()).unwrap();
        rngseed.assign_bytes(buffer.as_slice());
    })
}


#[ic_cdk::query]
fn greet(name: String) -> String {
    let ecda:signing::AsymmetricKeyImpl = signing::AsymmetricKeyImpl();

    let secret = ecda.parse_secret_key_from_hex(name.as_str()).unwrap();
    let keypar = ecda.new_keypair(secret).unwrap();
    let outstr = keypar.verifying_key().to_bytes().to_lower_hex_string();
    format!("Hello, {}!", outstr)
}

#[ic_cdk::query]
fn generate_key() -> String {
    let seed = GLOBAL_RNG_SEED.with(|rngseed| rngseed.borrow().inner.clone());
    let mut rngcore = CryptoHashRng::from_seed(seed);
    let ecda:signing::AsymmetricKeyImpl = signing::AsymmetricKeyImpl();
    let skey = ecda.generate_secret_key(&mut rngcore).unwrap();
    skey.to_bytes().to_lower_hex_string()
}

#[ic_cdk::query]
fn schnorr_signature(msg:String, skey_str: String) -> SIGNATURE_INFO {
    let seed = GLOBAL_RNG_SEED.with(|rngseed| rngseed.borrow().inner.clone());    
    let mut rngcore = CryptoHashRng::from_seed(seed);        
    let ecda:signing::AsymmetricKeyImpl = signing::AsymmetricKeyImpl();
    
    let skey = ecda.parse_secret_key(skey_str.as_str()).unwrap();
    let keypair = ecda.new_keypair(skey).unwrap();

    let rk = ecda.generate_signature(msg.as_str(), &keypair, &mut rngcore);
    let signature_data = rk.unwrap();

    let outpk = keypair.verifying_key().to_bytes().to_lower_hex_string();
    let outsignature = signature_data.to_bytes().to_lower_hex_string();

    SIGNATURE_INFO{signature_str:outsignature, verifying_key:outpk}
}

#[ic_cdk::query]
fn validate_schnorr(msg:String, validating_key_str: String, signature_str: String) -> bool {    
    let ecda:signing::AsymmetricKeyImpl = signing::AsymmetricKeyImpl();
    
    let verykey = ecda.parse_public_key(validating_key_str.as_str()).unwrap();
    let signature_data= ecda.parse_signature(&signature_str.as_str()).unwrap();

    ecda.verifying_signature(msg.as_str(),&verykey, &signature_data).is_ok()
}

// Enable Candid export
ic_cdk::export_candid!();