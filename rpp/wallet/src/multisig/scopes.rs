use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultisigScope {
    threshold: u8,
    participants: u8,
}

impl MultisigScope {
    pub fn new(threshold: u8, participants: u8) -> Result<Self, MultisigScopeError> {
        if threshold == 0 {
            return Err(MultisigScopeError::ZeroThreshold);
        }
        if participants == 0 {
            return Err(MultisigScopeError::ZeroParticipants);
        }
        if threshold > participants {
            return Err(MultisigScopeError::ThresholdExceedsParticipants);
        }
        Ok(Self {
            threshold,
            participants,
        })
    }

    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    pub fn participants(&self) -> u8 {
        self.participants
    }

    pub fn requires_collaboration(&self) -> bool {
        self.threshold > 1
    }

    pub fn parse(spec: &str) -> Result<Self, MultisigScopeError> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(MultisigScopeError::InvalidFormat);
        }
        let tokens: Vec<&str> = spec
            .split(|c| c == '-' || c == ' ')
            .filter(|token| !token.is_empty())
            .collect();
        if tokens.len() != 3 || !tokens[1].eq_ignore_ascii_case("of") {
            return Err(MultisigScopeError::InvalidFormat);
        }
        let threshold: u8 = tokens[0]
            .parse()
            .map_err(|_| MultisigScopeError::InvalidNumber(tokens[0].to_string()))?;
        let participants: u8 = tokens[2]
            .parse()
            .map_err(|_| MultisigScopeError::InvalidNumber(tokens[2].to_string()))?;
        Self::new(threshold, participants)
    }
}

impl fmt::Display for MultisigScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-of-{}", self.threshold, self.participants)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MultisigScopeError {
    #[error("invalid multisig scope format")]
    InvalidFormat,
    #[error("invalid number `{0}` in multisig scope")]
    InvalidNumber(String),
    #[error("threshold must be greater than zero")]
    ZeroThreshold,
    #[error("participants must be greater than zero")]
    ZeroParticipants,
    #[error("threshold cannot exceed participants")]
    ThresholdExceedsParticipants,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_scope() {
        let scope = MultisigScope::parse("2-of-3").expect("scope");
        assert_eq!(scope.threshold(), 2);
        assert_eq!(scope.participants(), 3);
    }

    #[test]
    fn parse_scope_accepts_whitespace_and_case() {
        let scope = MultisigScope::parse(" 3 OF 5 ").expect("scope");
        assert_eq!(scope.threshold(), 3);
        assert_eq!(scope.participants(), 5);
    }

    #[test]
    fn parse_rejects_invalid_format() {
        assert!(matches!(
            MultisigScope::parse("bad"),
            Err(MultisigScopeError::InvalidFormat)
        ));
        assert!(matches!(
            MultisigScope::parse("2/3"),
            Err(MultisigScopeError::InvalidFormat)
        ));
    }

    #[test]
    fn parse_rejects_invalid_numbers() {
        assert!(matches!(
            MultisigScope::parse("x-of-3"),
            Err(MultisigScopeError::InvalidNumber(value)) if value == "x"
        ));
        assert!(matches!(
            MultisigScope::parse("2-of-y"),
            Err(MultisigScopeError::InvalidNumber(value)) if value == "y"
        ));
    }

    #[test]
    fn new_validates_threshold_and_participants() {
        assert!(matches!(
            MultisigScope::new(0, 3),
            Err(MultisigScopeError::ZeroThreshold)
        ));
        assert!(matches!(
            MultisigScope::new(2, 0),
            Err(MultisigScopeError::ZeroParticipants)
        ));
        assert!(matches!(
            MultisigScope::new(3, 2),
            Err(MultisigScopeError::ThresholdExceedsParticipants)
        ));
    }

    #[test]
    fn requires_collaboration_detects_threshold() {
        let solo = MultisigScope::new(1, 3).expect("scope");
        assert!(!solo.requires_collaboration());
        let collaborative = MultisigScope::new(2, 3).expect("scope");
        assert!(collaborative.requires_collaboration());
    }
}
