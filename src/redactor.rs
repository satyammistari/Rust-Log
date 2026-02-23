use std::sync::Arc;

use regex::Regex;
use sha2::{Digest, Sha256};

use crate::error::Result;
use crate::patterns::PatternSet;

#[derive(Debug, Clone, PartialEq)]
pub enum ReplacementStyle {
    Fixed,   // Always outputs [REDACTED]
    Tagged,  // Outputs [EMAIL_REDACTED] [IPV4_REDACTED] etc
    Hashed,  // Outputs first 8 chars of SHA256 of original value
}

impl ReplacementStyle {
    pub fn from_str(s: &str) -> Self {
        match s {
            "fixed" => Self::Fixed,
            "hashed" => Self::Hashed,
            _ => Self::Tagged,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct RedactionStats {
    pub emails_redacted: u64,
    pub ipv4_redacted: u64,
    pub ipv6_redacted: u64,
    pub jwts_redacted: u64,
    pub api_keys_redacted: u64,
    pub aws_keys_redacted: u64,
    pub credit_cards_redacted: u64,
    pub uuids_redacted: u64,
    pub passwords_redacted: u64,
    pub total_redactions: u64,
    pub lines_processed: u64,
}

impl RedactionStats {
    pub fn merge(&mut self, other: &RedactionStats) {
        self.emails_redacted += other.emails_redacted;
        self.ipv4_redacted += other.ipv4_redacted;
        self.ipv6_redacted += other.ipv6_redacted;
        self.jwts_redacted += other.jwts_redacted;
        self.api_keys_redacted += other.api_keys_redacted;
        self.aws_keys_redacted += other.aws_keys_redacted;
        self.credit_cards_redacted += other.credit_cards_redacted;
        self.uuids_redacted += other.uuids_redacted;
        self.passwords_redacted += other.passwords_redacted;
        self.total_redactions += other.total_redactions;
        self.lines_processed += other.lines_processed;
    }
}

pub struct RedactorConfig {
    pub style: ReplacementStyle,
    pub skip_uuids: bool,
    pub skip_ips: bool,
    pub skip_emails: bool,
}

pub struct Redactor {
    pub patterns: Arc<PatternSet>,
    pub config: RedactorConfig,
}

impl Redactor {
    pub fn new(config: RedactorConfig) -> Result<Self> {
        Ok(Self {
            patterns: Arc::new(PatternSet::new()?),
            config,
        })
    }

    pub fn redact_line(&self, line: &str) -> (String, RedactionStats) {
        let mut result = line.to_string();
        let mut stats = RedactionStats::default();

        // Order matters — most specific patterns first
        // JWT before api_key to avoid partial matches

        // 1. JWT tokens
        let count = self.apply(&mut result, &self.patterns.jwt, "jwt");
        stats.jwts_redacted += count;

        // 2. AWS Access Key
        let count = self.apply(
            &mut result,
            &self.patterns.aws_access_key,
            "aws_access_key",
        );
        stats.aws_keys_redacted += count;

        // 3. AWS Secret Key
        let count = self.apply(
            &mut result,
            &self.patterns.aws_secret_key,
            "aws_secret_key",
        );
        stats.aws_keys_redacted += count;

        // 4. Private key headers
        let count = self.apply(
            &mut result,
            &self.patterns.private_key_header,
            "private_key",
        );
        stats.api_keys_redacted += count;

        // 5. Credit cards
        let count = self.apply(
            &mut result,
            &self.patterns.credit_card,
            "credit_card",
        );
        stats.credit_cards_redacted += count;

        // 6. Generic API keys and passwords
        let count = self.apply(&mut result, &self.patterns.api_key, "api_key");
        stats.api_keys_redacted += count;

        // 7. Password fields
        let count = self.apply(
            &mut result,
            &self.patterns.password_field,
            "password",
        );
        stats.passwords_redacted += count;

        // 8. Emails (unless skipped)
        if !self.config.skip_emails {
            let count = self.apply(&mut result, &self.patterns.email, "email");
            stats.emails_redacted += count;
        }

        // 9. IPv4 (unless skipped)
        if !self.config.skip_ips {
            let count = self.apply(&mut result, &self.patterns.ipv4, "ipv4");
            stats.ipv4_redacted += count;

            // 10. IPv6
            let count = self.apply(&mut result, &self.patterns.ipv6, "ipv6");
            stats.ipv6_redacted += count;
        }

        // 11. UUIDs (unless skipped)
        if !self.config.skip_uuids {
            let count = self.apply(&mut result, &self.patterns.uuid, "uuid");
            stats.uuids_redacted += count;
        }

        stats.total_redactions = stats.emails_redacted
            + stats.ipv4_redacted
            + stats.ipv6_redacted
            + stats.jwts_redacted
            + stats.api_keys_redacted
            + stats.aws_keys_redacted
            + stats.credit_cards_redacted
            + stats.uuids_redacted
            + stats.passwords_redacted;

        stats.lines_processed = 1;

        (result, stats)
    }

    fn apply(
        &self,
        text: &mut String,
        pattern: &Regex,
        pattern_type: &str,
    ) -> u64 {
        let count = pattern.find_iter(text).count() as u64;
        if count == 0 {
            return 0;
        }

        let replacement = match &self.config.style {
            ReplacementStyle::Fixed => "[REDACTED]".to_string(),
            ReplacementStyle::Tagged => {
                format!("[{}_REDACTED]", pattern_type.to_uppercase())
            }
            ReplacementStyle::Hashed => {
                // Hash each match separately
                // Use first 8 chars of SHA256
                let replaced = pattern.replace_all(text, |caps: &regex::Captures| {
                    let original = caps.get(0).map_or("", |m| m.as_str());
                    let mut hasher = Sha256::new();
                    hasher.update(original.as_bytes());
                    let result = hasher.finalize();
                    let hex_str: String = result[..4]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect();
                    format!("[{}]", hex_str)
                });
                *text = replaced.into_owned();
                return count;
            }
        };

        *text = pattern
            .replace_all(text, replacement.as_str())
            .into_owned();

        count
    }
}
