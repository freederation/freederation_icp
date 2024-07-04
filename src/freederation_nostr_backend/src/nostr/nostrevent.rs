use core::fmt;
use core::str::{FromStr};
use url::Url;
use std::string::{FromUtf8Error, String, ToString};
use serde::{Deserialize, Deserializer, Serialize};
use bech32::{Bech32};
use crate::nostr::event_id::EventId;
use crate::signing::{DataBytes, NostrPubKey};
use crate::nostr::event_kind::Kind;
use crate::util::basecore::ParseError as NParseError;
use crate::util::nostrbech32_params::{
    FromBech32, ToBech32, SPECIAL, HRP_EVENT, FIXED_1_1_32_BYTES_TVL, AUTHOR, KIND, RELAY
};

