use serde::{Deserialize, Deserializer, Serialize, Serializer};
use core::cmp::Ordering;

use crate::nostr::event_id::EventId;
use crate::nostr::event_error::EventDataError;
use crate::nostr::event_kind::Kind;
use crate::nostr::tag::TagData;
use crate::signing::{NostrPubKey, NostrSignature, AsymmetricKeyOps, AsymmetricKeyImpl, AsymmetricKeyError};
use crate::util::time::Timestamp;
use crate::util::basecore::ParseError;
use crate::util::jsonutil::JsonUtil;



/// Event Intermediate used for de/serialization of [`Event`]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventData {
    /// Id
    pub id: EventId,
    /// Author
    pub pubkey: NostrPubKey,
    /// Timestamp (seconds)
    pub created_at: Timestamp,
    /// Kind
    pub kind: Kind,
    /// Vector of [`Tag`]
    pub tags: Vec<TagData>,
    /// Content
    pub content: String,
    /// Signature
    pub sig: NostrSignature,
}

impl EventData {
    pub fn new<I,S>(
        id: EventId,
        public_key: NostrPubKey,
        created_at: Timestamp,
        kind: Kind,
        tags: I,
        content: S,
        sig: NostrSignature,
    ) -> Self 
    where
        I: IntoIterator<Item = TagData>,
        S: Into<String>,
    {
        Self { 
            id: id, pubkey: public_key, created_at: created_at, kind: kind,
            tags: tags.into_iter().collect(), content: content.into(), sig: sig
        }
    }

    pub fn verify_id(&self) -> Result<(),EventDataError>
    {
        let evid = EventId::new(
            &self.pubkey,
            &self.created_at, 
            &self.kind,
            self.tags.as_slice(),
            self.content.as_str()
        );

        if evid.eq(&self.id) == false {Err(EventDataError::InvalidEventHash)} else { Ok(()) }
    }

    pub fn verify_signature(&self) -> Result<(), EventDataError>
    {
        let ecda = AsymmetricKeyImpl();
        let res = ecda.verifying_signature_from_bytes(
            self.id.as_bytes(),
            &self.pubkey.0,
            &self.sig.0
        );
        res.map_err(EventDataError::InvalidEventSignature)
    }

    pub fn verify(&self) -> Result<(), EventDataError>
    {
        self.verify_id().and_then(|_|self.verify_signature())
    }
    
    /// Check POW
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/13.md>
    #[inline]
    pub fn check_pow(&self, difficulty: u8) -> bool {
        self.id.check_pow(difficulty)
    }

}

impl JsonUtil for EventData {
    type Err = ParseError;

    /// Deserialize [`Event`] from JSON
    ///
    /// **This method NOT verify the signature!**
    #[inline]
    fn from_json<T>(json: T) -> Result<Self, Self::Err>
    where
        T: AsRef<[u8]>,
    {
        serde_json::from_slice(
            json.as_ref()
        ).map_err (
        |e| ParseError::FromJSON(e)
        )
    }
}


impl PartialOrd for EventData {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EventData {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.created_at != other.created_at {
            // Ascending order
            // NOT EDIT, will break many things!!
            self.created_at.cmp(&other.created_at)
        } else {
            self.id.cmp(&other.id)
        }
    }
}
