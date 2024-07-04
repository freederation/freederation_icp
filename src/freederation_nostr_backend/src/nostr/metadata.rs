use std::collections::HashMap as AllocMap;
use serde::de::{Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use core::fmt;

use crate::util::jsonutil::JsonUtil;
use url::Url;

/// [`Metadata`] error
#[derive(Debug)]
pub enum MetadataError {
    /// Error serializing or deserializing JSON data
    Json(serde_json::Error),
}

impl std::error::Error for MetadataError {}

impl fmt::Display for MetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(e) => write!(f, "Json: {e}"),
        }
    }
}

impl From<serde_json::Error> for MetadataError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

/// Metadata
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    /// Name
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub name: Option<String>,
    /// Display name
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub display_name: Option<String>,
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub about: Option<String>,
    /// Website url
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub website: Option<String>,
    /// Picture url
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub picture: Option<String>,
    /// Banner url
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub banner: Option<String>,
    /// NIP05 (ex. name@example.com)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub nip05: Option<String>,
    /// LNURL
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub lud06: Option<String>,
    /// Lightning Address
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub lud16: Option<String>,
    /// Custom fields
    #[serde(
        flatten,
        serialize_with = "serialize_custom_fields",
        deserialize_with = "deserialize_custom_fields"
    )]
    #[serde(default)]
    pub custom: AllocMap<String, Value>,
}

impl Metadata {
    /// New empty [`Metadata`]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set name
    pub fn name<S>(self, name: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            name: Some(name.into()),
            ..self
        }
    }

    /// Set display name
    pub fn display_name<S>(self, display_name: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            display_name: Some(display_name.into()),
            ..self
        }
    }

    /// Set about
    pub fn about<S>(self, about: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            about: Some(about.into()),
            ..self
        }
    }

    /// Set website
    pub fn website(self, url: Url) -> Self {
        Self {
            website: Some(url.into()),
            ..self
        }
    }

    /// Set picture
    pub fn picture(self, url: Url) -> Self {
        Self {
            picture: Some(url.into()),
            ..self
        }
    }

    /// Set banner
    pub fn banner(self, url: Url) -> Self {
        Self {
            banner: Some(url.into()),
            ..self
        }
    }

    /// Set nip05
    pub fn nip05<S>(self, nip05: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            nip05: Some(nip05.into()),
            ..self
        }
    }

    /// Set lud06 (LNURL)
    pub fn lud06<S>(self, lud06: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            lud06: Some(lud06.into()),
            ..self
        }
    }

    /// Set lud16 (Lightning Address)
    pub fn lud16<S>(self, lud16: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            lud16: Some(lud16.into()),
            ..self
        }
    }

    /// Set custom metadata field
    pub fn custom_field<K, S>(mut self, field_name: K, value: S) -> Self
    where
        K: Into<String>,
        S: Into<Value>,
    {
        self.custom.insert(field_name.into(), value.into());
        self
    }
}

impl JsonUtil for Metadata {
    type Err = MetadataError;
}

fn serialize_custom_fields<S>(
    custom_fields: &AllocMap<String, Value>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut map = serializer.serialize_map(Some(custom_fields.len()))?;
    for (field_name, value) in custom_fields {
        map.serialize_entry(field_name, value)?;
    }
    map.end()
}

fn deserialize_custom_fields<'de, D>(deserializer: D) -> Result<AllocMap<String, Value>, D::Error>
where
    D: Deserializer<'de>,
{
    struct GenericTagsVisitor;

    impl<'de> Visitor<'de> for GenericTagsVisitor {
        type Value = AllocMap<String, Value>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("map where keys are strings and values are valid json")
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            #[cfg(not(feature = "std"))]
            let mut custom_fields: AllocMap<String, Value> = AllocMap::new();
            #[cfg(feature = "std")]
            let mut custom_fields: AllocMap<String, Value> =
                AllocMap::with_capacity(map.size_hint().unwrap_or_default());
            while let Some(field_name) = map.next_key::<String>()? {
                if let Ok(value) = map.next_value::<Value>() {
                    custom_fields.insert(field_name, value);
                }
            }
            Ok(custom_fields)
        }
    }

    deserializer.deserialize_map(GenericTagsVisitor)
}

#[cfg(test)]
mod tests {

    use super::*;

    use crate::util::uncheckedurl::UncheckedUrl;
    use core::{str::FromStr};

    #[test]
    fn test_unchecked_relay_url() {
        let relay = "wss://relay.damus.io/";
        let relay_url = Url::from_str(relay).unwrap();

        let unchecked_relay_url = UncheckedUrl::from(relay_url.clone());

        assert_eq!(unchecked_relay_url, UncheckedUrl::from(relay));

        assert_eq!(
            Url::try_from(unchecked_relay_url.clone()).unwrap(),
            relay_url
        );

        assert_eq!(relay, unchecked_relay_url.to_string());
    }
}
