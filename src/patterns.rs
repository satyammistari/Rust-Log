use regex::Regex;

use crate::error::Result;

pub struct PatternSet {
    pub email: Regex,
    pub ipv4: Regex,
    pub ipv6: Regex,
    pub jwt: Regex,
    pub aws_access_key: Regex,
    pub aws_secret_key: Regex,
    pub api_key: Regex,
    pub credit_card: Regex,
    pub uuid: Regex,
    pub private_key_header: Regex,
    pub password_field: Regex,
}

impl PatternSet {
    pub fn new() -> Result<Self> {
        Ok(Self {
            email: Regex::new(
                r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            )?,

            ipv4: Regex::new(
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            )?,

            ipv6: Regex::new(
                r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
            )?,

            jwt: Regex::new(
                r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
            )?,

            aws_access_key: Regex::new(r"AKIA[0-9A-Z]{16}")?,

            aws_secret_key: Regex::new(
                r#"(?i)(?:aws_secret_access_key|aws_secret)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#,
            )?,

            api_key: Regex::new(
                r#"(?i)(?:api[_\-]?key|token|secret|password|passwd|pwd)\s*[=:]\s*['"]?([a-zA-Z0-9_\-\.]{20,})['"]?"#,
            )?,

            credit_card: Regex::new(
                r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
            )?,

            uuid: Regex::new(
                r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            )?,

            private_key_header: Regex::new(
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            )?,

            password_field: Regex::new(
                r#"(?i)(?:password|passwd|pwd)\s*[=:]\s*['"]?(\S+)['"]?"#,
            )?,
        })
    }
}
