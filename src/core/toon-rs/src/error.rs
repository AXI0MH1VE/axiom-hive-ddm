// AxiomHive TOON Parser v2.1.0
// Error types for TOON parsing
// Zero Entropy Law: C=0 enforced

use std::fmt;

#[derive(Debug)]
pub enum TOONError {
    JsonDelimiterDetected,
    InvalidGuardrail,
    ParseError(String),
}

impl fmt::Display for TOONError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TOONError::JsonDelimiterDetected => {
                write!(f, "TOON Guardrail violation: JSON delimiter '{{' detected")
            }
            TOONError::InvalidGuardrail => {
                write!(f, "Invalid TOON format: expected key[count]{{schema}}")
            }
            TOONError::ParseError(msg) => {
                write!(f, "TOON parse error: {}", msg)
            }
        }
    }
}

impl std::error::Error for TOONError {}
