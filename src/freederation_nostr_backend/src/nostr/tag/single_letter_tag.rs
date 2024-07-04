use core::fmt;
use core::str::{FromStr};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Alphabet Error
#[derive(thiserror::Error, Debug)]
pub enum SingleLetterTagError {
    #[error("Invalid char")]
    InvalidChar,    
    #[error("Expected char")]
    ExpectedChar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Alphabet {
    A,
    B,
    C,
    D,
    E,
    F,
    G,
    H,
    I,
    J,
    K,
    L,
    M,
    N,
    O,
    P,
    Q,
    R,
    S,
    T,
    U,
    V,
    W,
    X,
    Y,
    Z,
}

/// Single-Letter Tag (a-zA-Z)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SingleLetterTag {
    /// Single-letter char
    pub character: Alphabet,
    /// Is the `character` uppercase?
    pub uppercase: bool,
}

impl SingleLetterTag {
    /// Compose new `lowercase` single-letter tag
    #[inline]
    pub fn lowercase(character: Alphabet) -> Self {
        Self {
            character,
            uppercase: false,
        }
    }

    /// Compose new `uppercase` single-letter tag
    #[inline]
    pub fn uppercase(character: Alphabet) -> Self {
        Self {
            character,
            uppercase: true,
        }
    }

    /// Parse single-letter tag from [char]
    pub fn from_char(c: char) -> Result<Self, SingleLetterTagError> {
        let character = match c {
            'a' | 'A' => Alphabet::A,
            'b' | 'B' => Alphabet::B,
            'c' | 'C' => Alphabet::C,
            'd' | 'D' => Alphabet::D,
            'e' | 'E' => Alphabet::E,
            'f' | 'F' => Alphabet::F,
            'g' | 'G' => Alphabet::G,
            'h' | 'H' => Alphabet::H,
            'i' | 'I' => Alphabet::I,
            'j' | 'J' => Alphabet::J,
            'k' | 'K' => Alphabet::K,
            'l' | 'L' => Alphabet::L,
            'm' | 'M' => Alphabet::M,
            'n' | 'N' => Alphabet::N,
            'o' | 'O' => Alphabet::O,
            'p' | 'P' => Alphabet::P,
            'q' | 'Q' => Alphabet::Q,
            'r' | 'R' => Alphabet::R,
            's' | 'S' => Alphabet::S,
            't' | 'T' => Alphabet::T,
            'u' | 'U' => Alphabet::U,
            'v' | 'V' => Alphabet::V,
            'w' | 'W' => Alphabet::W,
            'x' | 'X' => Alphabet::X,
            'y' | 'Y' => Alphabet::Y,
            'z' | 'Z' => Alphabet::Z,
            _ => return Err(SingleLetterTagError::InvalidChar),
        };

        Ok(Self {
            character,
            uppercase: c.is_uppercase(),
        })
    }

    /// Get as char
    pub fn as_char(&self) -> char {
        if self.uppercase {
            match self.character {
                Alphabet::A => 'A',
                Alphabet::B => 'B',
                Alphabet::C => 'C',
                Alphabet::D => 'D',
                Alphabet::E => 'E',
                Alphabet::F => 'F',
                Alphabet::G => 'G',
                Alphabet::H => 'H',
                Alphabet::I => 'I',
                Alphabet::J => 'J',
                Alphabet::K => 'K',
                Alphabet::L => 'L',
                Alphabet::M => 'M',
                Alphabet::N => 'N',
                Alphabet::O => 'O',
                Alphabet::P => 'P',
                Alphabet::Q => 'Q',
                Alphabet::R => 'R',
                Alphabet::S => 'S',
                Alphabet::T => 'T',
                Alphabet::U => 'U',
                Alphabet::V => 'V',
                Alphabet::W => 'W',
                Alphabet::X => 'X',
                Alphabet::Y => 'Y',
                Alphabet::Z => 'Z',
            }
        } else {
            match self.character {
                Alphabet::A => 'a',
                Alphabet::B => 'b',
                Alphabet::C => 'c',
                Alphabet::D => 'd',
                Alphabet::E => 'e',
                Alphabet::F => 'f',
                Alphabet::G => 'g',
                Alphabet::H => 'h',
                Alphabet::I => 'i',
                Alphabet::J => 'j',
                Alphabet::K => 'k',
                Alphabet::L => 'l',
                Alphabet::M => 'm',
                Alphabet::N => 'n',
                Alphabet::O => 'o',
                Alphabet::P => 'p',
                Alphabet::Q => 'q',
                Alphabet::R => 'r',
                Alphabet::S => 's',
                Alphabet::T => 't',
                Alphabet::U => 'u',
                Alphabet::V => 'v',
                Alphabet::W => 'w',
                Alphabet::X => 'x',
                Alphabet::Y => 'y',
                Alphabet::Z => 'z',
            }
        }
    }

    /// Check if single-letter tag is `lowercase`
    #[inline]
    pub fn is_lowercase(&self) -> bool {
        !self.uppercase
    }

    /// Check if single-letter tag is `uppercase`
    #[inline]
    pub fn is_uppercase(&self) -> bool {
        self.uppercase
    }
}

impl fmt::Display for SingleLetterTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_char())
    }
}

impl FromStr for SingleLetterTag {
    type Err = SingleLetterTagError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() == 1 {
            let c: char = s.chars().next().ok_or(SingleLetterTagError::ExpectedChar)?;
            Self::from_char(c)
        } else {
            Err(SingleLetterTagError::ExpectedChar)
        }
    }
}

impl Serialize for SingleLetterTag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_char(self.as_char())
    }
}

impl<'de> Deserialize<'de> for SingleLetterTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let character: char = char::deserialize(deserializer)?;
        Self::from_char(character).map_err(serde::de::Error::custom)
    }
}