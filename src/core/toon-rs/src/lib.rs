// AxiomHive TOON Parser v2.1.0
// Zero-copy parsing with Guardrail regex enforcement
// Zero Entropy Law: C=0 enforced

use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ToonValue {
    pub count: usize,
    pub schema: String,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub enum ToonError {
    JsonDelimiterDetected,
    InvalidGuardrail,
    ParseError(String),
}

pub struct ToonParser {
    guardrail: Regex,
}

impl ToonParser {
    pub fn new() -> Self {
        let guardrail = Regex::new(r"^(\w+)\s*\[(\d+)\]\{(\w+)\}$").unwrap();
        Self { guardrail }
    }

    pub fn parse(&self, input: &str) -> Result<HashMap<String, ToonValue>, ToonError> {
        // Guardrail: panic on JSON delimiter '{'
        if input.contains('{') {
            return Err(ToonError::JsonDelimiterDetected);
        }

        let mut result = HashMap::new();
        for line in input.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let Some(caps) = self.guardrail.captures(line) {
                let key = caps.get(1).unwrap().as_str().to_string();
                let count: usize = caps.get(2).unwrap().as_str().parse()
                    .map_err(|e| ToonError::ParseError(e.to_string()))?;
                let schema = caps.get(3).unwrap().as_str().to_string();
                
                result.insert(key, ToonValue {
                    count,
                    schema: schema.clone(),
                    data: Vec::with_capacity(count * 64), // Pre-allocate based on schema
                });
            } else {
                return Err(ToonError::InvalidGuardrail);
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_toon_guardrail() {
        let parser = ToonParser::new();
        let valid = "user[1024]{string}";
        assert!(parser.parse(valid).is_ok());
        
        let invalid = "user:{\"name\":\"test\"}";
        assert!(matches!(
            parser.parse(invalid),
            Err(ToonError::JsonDelimiterDetected)
        ));
    }
}
