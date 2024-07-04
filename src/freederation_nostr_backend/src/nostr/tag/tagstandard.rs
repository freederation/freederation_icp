use core::str::{FromStr};
use url::Url;
use k256::sha2::{Digest, Sha256};
use hex_conservative::{FromHex, DisplayHex};

use crate::nostr::event_id::EventId;
use crate::nostr::event_kind::Kind;
use crate::nostr::event_data::EventData;
use crate::signing::{NostrPubKey, NostrSecretKey, NostrSignature};
use crate::util::uncheckedurl::UncheckedUrl;
use crate::util::time::Timestamp;
use crate::util::nostrimage::ImageDimensions;
use crate::util::basecore::{DataBytes};

use crate::nostr::tag::marker::Marker;
use crate::nostr::tag::report::Report;
use crate::nostr::tag::relaymetadata::RelayMetadata;
use crate::nostr::tag::coordinate::Coordinate;
use crate::nostr::tag::delegation::{Conditions,DelegationTag};
use crate::nostr::tag::nostrhttpmethod::NostrHttpMethod;
use crate::nostr::tag::tagerror::TagError;
use crate::nostr::tag::tagkind::TagKind;


/// Standardized tag
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TagStandard {
    /// Not processed yey
    NotProcessed,
    
    /// A valid tag that is not implemented yet
    Uncategorized(String),
    
    /// A tag with parsicng errors
    Malformed,
    
    /// Event
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md> and <https://github.com/nostr-protocol/nips/blob/master/10.md>
    Event {
        event_id: EventId,
        relay_url: Option<UncheckedUrl>,
        marker: Option<Marker>,
        /// Should be the public key of the author of the referenced event
        public_key: Option<NostrPubKey>,
    },
    
    /// Report event
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/56.md>
    EventReport(EventId, Report),
    /// Public Key
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    PublicKey {
        public_key: NostrPubKey,
        relay_url: Option<UncheckedUrl>,
        alias: Option<String>,
        /// Whether the p tag is an uppercase P or not
        uppercase: bool,
    },
    /// Report public key
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/56.md>
    PublicKeyReport(NostrPubKey, Report),
    Reference(String),
    /// Relay Metadata
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/65.md>
    RelayMetadata {
        relay_url: Url,
        metadata: Option<RelayMetadata>,
    },
    Hashtag(String),
    Geohash(String),
    Identifier(String),    
    Coordinate {
        coordinate: Coordinate,
        relay_url: Option<UncheckedUrl>,
    },
    Kind(Kind),
    Relay(UncheckedUrl),
    /// Proof of Work
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/13.md>
    POW {
        nonce: u128,
        difficulty: u8,
    },
    Delegation {
        delegator: NostrPubKey,
        conditions: Conditions,
        sig: NostrSignature,
    },
    ContentWarning {
        reason: Option<String>,
    },
    Expiration(Timestamp),
    Subject(String),
    Challenge(String),
    Title(String),
    Image(UncheckedUrl, Option<ImageDimensions>),
    Thumb(UncheckedUrl, Option<ImageDimensions>),
    Summary(String),
    Description(String),
    Bolt11(String),
    Preimage(String),
    Relays(Vec<UncheckedUrl>),
    Name(String),
    PublishedAt(Timestamp),
    Url(Url),
    MimeType(String),
    Aes256Gcm {
        key: String,
        iv: String,
    },
    Sha256(DataBytes),
    Size(usize),
    Dim(ImageDimensions),
    Magnet(String),
    Blurhash(String),
    Method(NostrHttpMethod),
    AbsoluteURL(UncheckedUrl),    
    Payload(DataBytes),
    Anon {
        msg: Option<String>,
    },    
    Emoji {
        /// Name given for the emoji, which MUST be comprised of only alphanumeric characters and underscores
        shortcode: String,
        /// URL to the corresponding image file of the emoji
        url: UncheckedUrl,
    },
    Encrypted,
    Request(EventData),
    Word(String),
    /// Label namespace
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/32.md>
    LabelNamespace(String),
    /// Label
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/32.md>
    Label(Vec<String>),
}

impl Default for TagStandard
{
    fn default() -> Self {
        TagStandard::NotProcessed
    }
}


impl TagStandard
{
    pub fn parse<S>(params:&[S]) -> Result<Self, TagError>
    where S: AsRef<str>
    {
        let tag_kind: TagKind = match params.first() {
            Some(kind) => TagKind::from(kind.as_ref()),
            None => return Err(TagError::KindNotFound),
        };

        Self::internal_parse(tag_kind, params)
    }

    fn internal_parse<S>(tag_kind: TagKind, params: &[S]) -> Result<Self, TagError>
    where
        S: AsRef<str>,
    {
        /*
        match tag_kind {
            TagKind::SingleLetter(single_letter) => match single_letter {
                // Parse `a` tag
                SingleLetterTag {
                    character: Alphabet::A,
                    uppercase: false,
                } => {
                    return parse_a_tag(tag);
                }
                // Parse `e` tag
                SingleLetterTag {
                    character: Alphabet::E,
                    uppercase: false,
                } => {
                    return parse_e_tag(tag);
                }
                // Parse `l` tag
                SingleLetterTag {
                    character: Alphabet::L,
                    uppercase: false,
                } => {
                    let labels = tag.iter().skip(1).map(|u| u.as_ref().to_string()).collect();
                    return Ok(Self::Label(labels));
                }
                // Parse `p` tag
                SingleLetterTag {
                    character: Alphabet::P,
                    uppercase,
                } => {
                    return parse_p_tag(tag, uppercase);
                }
                _ => (), // Covered later
            },
            TagKind::Anon => {
                return Ok(Self::Anon {
                    msg: extract_optional_string(tag, 1).map(|s| s.to_string()),
                })
            }
            TagKind::ContentWarning => {
                return Ok(Self::ContentWarning {
                    reason: extract_optional_string(tag, 1).map(|s| s.to_string()),
                })
            }
            TagKind::Delegation => return parse_delegation_tag(tag),
            TagKind::Encrypted => return Ok(Self::Encrypted),
            TagKind::Relays => {
                // Relays vec is of unknown length so checked here based on kind
                let urls = tag
                    .iter()
                    .skip(1)
                    .map(|u| UncheckedUrl::from(u.as_ref()))
                    .collect::<Vec<UncheckedUrl>>();
                return Ok(Self::Relays(urls));
            }
            _ => (), // Covered later
        };

        let tag_len: usize = tag.len();

        if tag_len == 2 {
            let tag_1: &str = tag[1].as_ref();

            return match tag_kind {
                TagKind::SingleLetter(SingleLetterTag {
                    character: Alphabet::R,
                    uppercase: false,
                }) => {
                    if tag_1.starts_with("ws://") || tag_1.starts_with("wss://") {
                        Ok(Self::RelayMetadata {
                            relay_url: Url::parse(tag_1)?,
                            metadata: None,
                        })
                    } else {
                        Ok(Self::Reference(tag_1.to_string()))
                    }
                }
                TagKind::SingleLetter(SingleLetterTag {
                    character: Alphabet::T,
                    uppercase: false,
                }) => Ok(Self::Hashtag(tag_1.to_string())),
                TagKind::SingleLetter(SingleLetterTag {
                    character: Alphabet::G,
                    uppercase: false,
                }) => Ok(Self::Geohash(tag_1.to_string())),
                TagKind::SingleLetter(SingleLetterTag {
                    character: Alphabet::D,
                    uppercase: false,
                }) => Ok(Self::Identifier(tag_1.to_string())),
                TagKind::SingleLetter(SingleLetterTag {
                    character: Alphabet::K,
                    uppercase: false,
                }) => Ok(Self::Kind(Kind::from_str(tag_1)?)),
                TagKind::SingleLetter(SingleLetterTag {
                    character: Alphabet::M,
                    uppercase: false,
                }) => Ok(Self::MimeType(tag_1.to_string())),
                TagKind::SingleLetter(SingleLetterTag {
                    character: Alphabet::X,
                    uppercase: false,
                }) => Ok(Self::Sha256(Sha256Hash::from_str(tag_1)?)),
                TagKind::SingleLetter(SingleLetterTag {
                    character: Alphabet::U,
                    uppercase: false,
                }) => Ok(Self::AbsoluteURL(UncheckedUrl::from(tag_1))),
                TagKind::Relay => Ok(Self::Relay(UncheckedUrl::from(tag_1))),
                TagKind::Expiration => Ok(Self::Expiration(Timestamp::from_str(tag_1)?)),
                TagKind::Subject => Ok(Self::Subject(tag_1.to_string())),
                TagKind::Challenge => Ok(Self::Challenge(tag_1.to_string())),
                TagKind::Title => Ok(Self::Title(tag_1.to_string())),
                TagKind::Image => Ok(Self::Image(UncheckedUrl::from(tag_1), None)),
                TagKind::Thumb => Ok(Self::Thumb(UncheckedUrl::from(tag_1), None)),
                TagKind::Summary => Ok(Self::Summary(tag_1.to_string())),
                TagKind::PublishedAt => Ok(Self::PublishedAt(Timestamp::from_str(tag_1)?)),
                TagKind::Description => Ok(Self::Description(tag_1.to_string())),
                TagKind::Bolt11 => Ok(Self::Bolt11(tag_1.to_string())),
                TagKind::Preimage => Ok(Self::Preimage(tag_1.to_string())),
                TagKind::Amount => Ok(Self::Amount {
                    millisats: tag_1.parse()?,
                    bolt11: None,
                }),
                TagKind::Lnurl => Ok(Self::Lnurl(tag_1.to_string())),
                TagKind::Name => Ok(Self::Name(tag_1.to_string())),
                TagKind::Url => Ok(Self::Url(Url::parse(tag_1)?)),
                TagKind::Magnet => Ok(Self::Magnet(tag_1.to_string())),
                TagKind::Blurhash => Ok(Self::Blurhash(tag_1.to_string())),
                TagKind::Streaming => Ok(Self::Streaming(UncheckedUrl::from(tag_1))),
                TagKind::Recording => Ok(Self::Recording(UncheckedUrl::from(tag_1))),
                TagKind::Starts => Ok(Self::Starts(Timestamp::from_str(tag_1)?)),
                TagKind::Ends => Ok(Self::Ends(Timestamp::from_str(tag_1)?)),
                TagKind::Status => match DataVendingMachineStatus::from_str(tag_1) {
                    Ok(status) => Ok(Self::DataVendingMachineStatus {
                        status,
                        extra_info: None,
                    }),
                    Err(_) => Ok(Self::LiveEventStatus(LiveEventStatus::from(tag_1))), /* TODO: check if unknown status error? */
                },
                TagKind::CurrentParticipants => Ok(Self::CurrentParticipants(tag_1.parse()?)),
                TagKind::TotalParticipants => Ok(Self::TotalParticipants(tag_1.parse()?)),
                TagKind::Method => Ok(Self::Method(HttpMethod::from_str(tag_1)?)),
                TagKind::Payload => Ok(Self::Payload(Sha256Hash::from_str(tag_1)?)),
                TagKind::Request => Ok(Self::Request(Event::from_json(tag_1)?)),
                TagKind::Word => Ok(Self::Word(tag_1.to_string())),
                TagKind::SingleLetter(SingleLetterTag {
                    character: Alphabet::L,
                    uppercase: true,
                }) => Ok(Self::LabelNamespace(tag_1.to_string())),
                TagKind::Dim => Ok(Self::Dim(ImageDimensions::from_str(tag_1)?)),
                _ => Err(Error::UnknownStardardizedTag),
            };
        }

        if tag_len == 3 {
            let tag_1: &str = tag[1].as_ref();
            let tag_2: &str = tag[2].as_ref();

            return match tag_kind {
                TagKind::SingleLetter(SingleLetterTag {
                    character: Alphabet::I,
                    uppercase: false,
                }) => Ok(Self::ExternalIdentity(Identity::new(tag_1, tag_2)?)),
                TagKind::Nonce => Ok(Self::POW {
                    nonce: tag_1.parse()?,
                    difficulty: tag_2.parse()?,
                }),
                TagKind::Image => Ok(Self::Image(
                    UncheckedUrl::from(tag_1),
                    Some(ImageDimensions::from_str(tag_2)?),
                )),
                TagKind::Thumb => Ok(Self::Thumb(
                    UncheckedUrl::from(tag_1),
                    Some(ImageDimensions::from_str(tag_2)?),
                )),
                TagKind::Aes256Gcm => Ok(Self::Aes256Gcm {
                    key: tag_1.to_string(),
                    iv: tag_2.to_string(),
                }),
                TagKind::SingleLetter(SingleLetterTag {
                    character: Alphabet::R,
                    uppercase: false,
                }) => {
                    if (tag_1.starts_with("ws://") || tag_1.starts_with("wss://"))
                        && !tag_2.is_empty()
                    {
                        Ok(Self::RelayMetadata {
                            relay_url: Url::parse(tag_1)?,
                            metadata: Some(RelayMetadata::from_str(tag_2)?),
                        })
                    } else {
                        Err(Error::UnknownStardardizedTag)
                    }
                }
                TagKind::Proxy => Ok(Self::Proxy {
                    id: tag_1.to_string(),
                    protocol: Protocol::from(tag_2),
                }),
                TagKind::Emoji => Ok(Self::Emoji {
                    shortcode: tag_1.to_string(),
                    url: UncheckedUrl::from(tag_2),
                }),
                TagKind::Status => match DataVendingMachineStatus::from_str(tag_1) {
                    Ok(status) => Ok(Self::DataVendingMachineStatus {
                        status,
                        extra_info: Some(tag_2.to_string()),
                    }),
                    Err(_) => Err(Error::UnknownStardardizedTag),
                },
                _ => Err(Error::UnknownStardardizedTag),
            };
        }

        Err(Error::UnknownStardardizedTag)

         */

        todo!()
    }

    /// Compose `TagStandard::Event` without `relay_url` and `marker`
    ///
    /// JSON: `["e", "event-id"]`    
    pub fn event(event_id: EventId) -> Self {
        Self::Event {
            event_id,
            relay_url: None,
            marker: None,
            public_key: None,
        }
    }
}

fn parse_e_tag<S>(tag: &[S]) -> Result<TagStandard, TagError>
where
    S: AsRef<str>,
{
    if tag.len() >= 2 {
        let event_id: EventId = EventId::from_hex(tag[1].as_ref())?;

        let tag_2: Option<&str> = tag.get(2).map(|r| r.as_ref());
        let tag_3: Option<&str> = tag.get(3).map(|r| r.as_ref());
        let tag_4: Option<&str> = tag.get(4).map(|r| r.as_ref());

        // Check if it's a report
        if let Some(tag_2) = tag_2 {
            return match Report::from_str(tag_2) {
                Ok(report) => Ok(TagStandard::EventReport(event_id, report)),
                Err(_) => Ok(TagStandard::Event {
                    event_id,
                    relay_url: (!tag_2.is_empty()).then_some(UncheckedUrl::from(tag_2)),
                    marker: tag_3.and_then(|t| (!t.is_empty()).then_some(Marker::from(t))),
                    public_key: match tag_4 {
                        Some(public_key) => Some(NostrPubKey::from_str(public_key).map_err(|e| TagError::Keys(e)) ?),
                        None => None,
                    },
                }),
            };
        }

        Ok(TagStandard::event(event_id))
    } else {
        Err(TagError::UnknownStardardizedTag)
    }
}