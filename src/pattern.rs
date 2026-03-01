use thiserror::Error;

#[derive(Error, Debug)]
pub enum PatternError {
    #[error("Invalid byte in pattern: {0}")]
    InvalidByte(String),
}

pub struct Pattern {
    pub pattern: Vec<u8>,
    pub mask: Vec<bool>,
}

impl Pattern {
    pub fn new(pattern: &str) -> Result<Self, PatternError> {
        let mut bytes = Vec::new();
        let mut mask = Vec::new();

        for part in pattern.split_whitespace() {
            if part == "?" || part == "??" {
                bytes.push(0);
                mask.push(false);
            } else {
                // convert hex string to u8
                match u8::from_str_radix(part, 16) {
                    Ok(byte) => {
                        bytes.push(byte);
                        mask.push(true);
                    }
                    Err(_) => return Err(PatternError::InvalidByte(part.to_string())),
                }
            }
        }

        Ok(Self {
            pattern: bytes,
            mask,
        })
    }

    pub fn matches(&self, data: &[u8]) -> bool {
        for (i, byte) in self.pattern.iter().enumerate() {
            if self.mask[i] && data[i] != *byte {
                return false;
            }
        }
        true
    }
}

impl std::fmt::Display for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        for (byte, &is_fixed) in self.pattern.iter().zip(self.mask.iter()) {
            if is_fixed {
                parts.push(format!("{:02X}", byte));
            } else {
                parts.push("?".to_string());
            }
        }
        write!(f, "{}", parts.join(" "))
    }
}
