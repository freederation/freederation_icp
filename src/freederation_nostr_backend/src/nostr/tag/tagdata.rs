use std::string::{String, ToString};
use std::vec::Vec;
use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use serde::de::Error as DeserializerError;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::nostr::tag::tagerror::TagError;

/// Tag
#[derive(Debug, Clone)]
pub struct TagData {
    buf: Vec<String>
}

impl PartialEq for TagData {
    fn eq(&self, other: &Self) -> bool {
        self.buf == other.buf
    }
}

impl Eq for TagData {}

impl PartialOrd for TagData {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TagData {
    fn cmp(&self, other: &Self) -> Ordering {
        self.buf.cmp(&other.buf)
    }
}

impl Hash for TagData {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.buf.hash(state);
    }
}

impl TagData {
    #[inline]
    fn new(buf: Vec<String>) -> Self {
        Self {
            buf
        }
    }

    
    /// Parse tag
    ///
    /// Return error if the tag is empty!
    pub fn parse<S>(tag: &[S]) -> Result<Self, TagError>
    where
        S: AsRef<str>,
    {
        // Check if it's empty
        if tag.is_empty() {
            return Err(TagError::EmptyTag);
        }

        // NOT USE `Self::new`!
        Ok(Self::new(
            tag.iter().map(|v| v.as_ref().to_string()).collect(),
        ))
    }

    /// Get tag kind
    #[inline]
    pub fn kind_str(&self) -> Option<&str> {
        self.buf.get(0).map(|s| s.as_str())
    }

    /// Return the **first** tag value (index `1`), if exists.
    #[inline]
    pub fn content(&self) -> Option<&str> {
        self.buf.get(1).map(|s| s.as_str())
    }

    /// Get reference of array of strings
    #[inline]
    pub fn as_vec(&self) -> &[String] {
        &self.buf
    }

    /// Consume tag and return array of strings
    #[inline]
    pub fn to_vec(self) -> Vec<String> {
        self.buf
    }
}


impl Serialize for TagData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.buf.len()))?;
        for element in self.buf.iter() {
            seq.serialize_element(&element)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for TagData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        type Data = Vec<String>;
        let tag: Vec<String> = Data::deserialize(deserializer)?;
        Self::parse(&tag).map_err(DeserializerError::custom)
    }
}