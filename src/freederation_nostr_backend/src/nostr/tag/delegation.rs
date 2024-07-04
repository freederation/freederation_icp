use core::fmt;
use std::str::FromStr;

use candid::de;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};
use serde::de::Error as DeserializerError;

use crate::signing::{AsymmetricKeyError, NostrPubKey, NostrSignature, NostrSecretKey, AsymmetricKeyOps, AsymmetricKeyImpl};
pub use crate::rng::CryptoRngCore as DelegationRngCore;
use crate::util::basecore::ParseError;


const DELEGATION_KEYWORD: &str = "delegation";

/// Tag validation errors
#[derive(thiserror::Error, Debug)]
pub enum ValidationError {
    
    #[error("Signature does not match")]
    InvalidSignature,
        
    #[error("Event kind does not match")]
    InvalidKind,
    
    #[error("Creation time is earlier than validity period")]
    CreatedTooEarly,

    #[error("Creation time is later than validity period")]
    CreatedTooLate,
}

#[derive(thiserror::Error, Debug)]
pub enum ConditionError {
    
    #[error("Encryption error:{0}")]
    Keys(#[from] AsymmetricKeyError),
    
    #[error("Parsing error: {0}")]
    Parsing(#[from ]ParseError),

    #[error("Cannot parse Invalid Condition")]
    ConditionsParseInvalidCondition,
    
    #[error("Conditions not satisfied: {0}")]
    ConditionsValidation(#[from] ValidationError),    
    
    
    #[error("Delegation tag parse error")]
    DelegationTagParse,
}


/// A condition from the delegation conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Condition {
    /// Event kind, e.g. kind=1
    Kind(u16),
    /// Creation time before, e.g. created_at<1679000000
    CreatedBefore(u64),
    /// Creation time after, e.g. created_at>1676000000
    CreatedAfter(u64),
}

/// Represents properties of an event, relevant for delegation
pub struct EventProperties {
    /// Event kind. For simplicity/flexibility, numeric type is used.
    kind: u16,
    /// Creation time, as unix timestamp
    created_time: u64,
}

impl EventProperties {
    /// Create new with values
    #[inline]
    pub fn new(event_kind: u16, created_time: u64) -> Self {
        Self {
            kind: event_kind,
            created_time,
        }
    }

    /*
    pub fn from_event(event: &Event) -> Self {
        Self {
            kind: event.kind().as_u16(),
            created_time: event.created_at().as_u64(),
        }
    } */
}

impl Condition {
    /// Evaluate whether an event satisfies this condition
    pub(crate) fn evaluate(&self, ep: &EventProperties) -> Result<(), ValidationError> {
        match self {
            Self::Kind(k) => {
                if ep.kind != *k {
                    return Err(ValidationError::InvalidKind);
                }
            }
            Self::CreatedBefore(t) => {
                if ep.created_time >= *t {
                    return Err(ValidationError::CreatedTooLate);
                }
            }
            Self::CreatedAfter(t) => {
                if ep.created_time <= *t {
                    return Err(ValidationError::CreatedTooEarly);
                }
            }
        }
        Ok(())
    }
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kind(k) => write!(f, "kind={k}"),
            Self::CreatedBefore(t) => write!(f, "created_at<{t}"),
            Self::CreatedAfter(t) => write!(f, "created_at>{t}"),
        }
    }
}

impl FromStr for Condition {
    type Err = ConditionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(kind) = s.strip_prefix("kind=") {
            let n = u16::from_str(kind).map_err(|e| ConditionError::Parsing(ParseError::ParseInt(e)))?;
            return Ok(Self::Kind(n));
        }
        if let Some(created_before) = s.strip_prefix("created_at<") {
            let n = u64::from_str(created_before).map_err(|e| ConditionError::Parsing(ParseError::ParseInt(e)))?;
            return Ok(Self::CreatedBefore(n));
        }
        if let Some(created_after) = s.strip_prefix("created_at>") {
            let n = u64::from_str(created_after).map_err(|e| ConditionError::Parsing(ParseError::ParseInt(e)))?;
            return Ok(Self::CreatedAfter(n));
        }
        Err(ConditionError::ConditionsParseInvalidCondition)
    }
}

/// Set of conditions of a delegation.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Conditions(Vec<Condition>);

impl Conditions {
    /// New empty [`Conditions`]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add [`Condition`]
    #[inline]
    pub fn add(&mut self, cond: Condition) {
        self.0.push(cond);
    }

    /// Evaluate whether an event satisfies all these conditions
    fn evaluate(&self, ep: &EventProperties) -> Result<(), ValidationError> {
        for c in &self.0 {
            c.evaluate(ep)?;
        }
        Ok(())
    }

    /// Get [`Vec<Condition>`]
    #[inline]
    pub fn inner(&self) -> Vec<Condition> {
        self.0.clone()
    }
}

impl fmt::Display for Conditions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Convert parts, join
        let conditions: String = self
            .0
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<String>>()
            .join("&");
        write!(f, "{conditions}")
    }
}

impl FromStr for Conditions {
    type Err = ConditionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Ok(Self::new());
        }
        let cond = s
            .split('&')
            .map(Condition::from_str)
            .collect::<Result<Vec<Condition>, Self::Err>>()?;
        Ok(Self(cond))
    }
}

impl Serialize for Conditions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Conditions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let json_value = Value::deserialize(deserializer)?;
        let conditions: String =
            serde_json::from_value(json_value).map_err(DeserializerError::custom)?;
        Self::from_str(&conditions).map_err(DeserializerError::custom)
    }
}


pub type DelegationSigningKey = <AsymmetricKeyImpl as AsymmetricKeyOps>::SigningKey;
pub type DelegationSignature = <AsymmetricKeyImpl as AsymmetricKeyOps>::Signature;

/// Delegation signature
#[derive(Clone)]
pub struct DelegationToken{
    token:String
}


impl DelegationToken {
    /// Generate [`DelegationToken`]
    #[inline]
    pub fn new(delegatee_pkey: &NostrPubKey, conditions: &Conditions) -> Result<Self, AsymmetricKeyError>  {
        
        Ok(Self{
            token: format!("{}:{DELEGATION_KEYWORD}:{delegatee_pkey}:{conditions}",crate::nostr::tag::nostruri::SCHEME)
        })
    }

    /// Get as bytes
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.token.as_bytes()
    }

    pub fn generate_signature<RG>(&self, delegator_skey: &DelegationSigningKey, rngcore:&mut RG) -> Result<NostrSignature, AsymmetricKeyError>
    where RG: DelegationRngCore
    {
        let ecda = AsymmetricKeyImpl();        
        Ok(NostrSignature(ecda.generate_signature_from_bytes(self.as_bytes(), &delegator_skey, rngcore)?))
    }

    pub fn verify_signature(&self, delegator_pkey: &NostrPubKey, signature: &NostrSignature) -> Result<(), AsymmetricKeyError> {
        let ecda = AsymmetricKeyImpl();
        ecda.verifying_signature_from_bytes(self.as_bytes(), &delegator_pkey.0, &signature.0)
    }
}

impl fmt::Display for DelegationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.token)
    }
}


/*************************************/

/// Delegation tag, as defined in NIP-26
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DelegationTag {
    delegator_pubkey: NostrPubKey,
    conditions: Conditions,
    signature: NostrSignature,
}


impl DelegationTag
{
    pub fn new<RG : CryptoRngCore>(
        delegator_skey: &DelegationSigningKey, 
        delegatee_pkey: NostrPubKey,
        conditions: Conditions,
        rng : &mut RG) -> Result<Self, AsymmetricKeyError>

    {
        let dtoken = DelegationToken::new(&delegatee_pkey, &conditions)?;
        let signvalue = dtoken.generate_signature(delegator_skey, rng)?;
        let ecda = AsymmetricKeyImpl();
        let dpk = NostrPubKey(ecda.pubkey_from_pair(delegator_skey));
        Ok(Self { delegator_pubkey: dpk, conditions: conditions, signature: signvalue })
    }

    pub fn validate(&self, delegatee_pkey: &NostrPubKey, conditions: &Conditions) -> Result<(), ConditionError> {
        let dtoken = DelegationToken::new(&delegatee_pkey, &conditions)?;
        dtoken.verify_signature(&self.delegator_pubkey, &self.signature).map_err(|e|e.into())
    }

    /// Convert to JSON string.
    pub fn as_json(&self) -> String {
        let tag = json!([
            DELEGATION_KEYWORD,
            self.delegator_pubkey.to_string(),
            self.conditions.to_string(),
            self.signature.to_string(),
        ]);
        tag.to_string()
    }

    /// Parse from a JSON string
    pub fn from_json(s: &str) -> Result<Self, ConditionError> {
        let tag: Vec<String> = serde_json::from_str(s).map_err(|_| ConditionError::DelegationTagParse)?;
        Self::try_from(tag)
    }

    /// Get delegator public key
    #[inline]
    pub fn delegator_pubkey(&self) -> NostrPubKey {
        self.delegator_pubkey.clone()
    }

    /// Get conditions
    #[inline]
    pub fn conditions(&self) -> Conditions {
        self.conditions.clone()
    }

    /// Get signature
    #[inline]
    pub fn signature(&self) -> NostrSignature {
        self.signature.clone()
    }
}

impl TryFrom<Vec<String>> for DelegationTag {
    type Error = ConditionError;

    fn try_from(tag: Vec<String>) -> Result<Self, Self::Error> {
        if tag.len() != 4 {
            return Err(ConditionError::DelegationTagParse);
        }
        if tag[0] != DELEGATION_KEYWORD {
            return Err(ConditionError::DelegationTagParse);
        }
        Ok(Self {
            delegator_pubkey: NostrPubKey::from_str(&tag[1])?,
            conditions: Conditions::from_str(&tag[2])?,
            signature: NostrSignature::from_str(&tag[3])?,
        })
    }
}

impl fmt::Display for DelegationTag {
    /// Return tag in JSON string format
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_json())
    }
}

impl FromStr for DelegationTag {
    type Err = ConditionError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_json(s)
    }
}