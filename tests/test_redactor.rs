use log_anonymizer::redactor::{Redactor, RedactorConfig, ReplacementStyle};

fn make_redactor() -> Redactor {
    Redactor::new(RedactorConfig {
        style: ReplacementStyle::Tagged,
        skip_uuids: false,
        skip_ips: false,
        skip_emails: false,
    })
    .unwrap()
}

#[test]
fn test_private_key_header_redacted() {
    let r = make_redactor();
    let (out, stats) = r.redact_line(
        "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA...",
    );
    assert!(out.contains("[PRIVATE_KEY_REDACTED]"));
    assert!(stats.api_keys_redacted >= 1);
}

#[test]
fn test_credit_card_redacted() {
    let r = make_redactor();
    let (out, stats) = r.redact_line("payment card 4111111111111111 approved");
    assert!(out.contains("[CREDIT_CARD_REDACTED]"));
    assert_eq!(stats.credit_cards_redacted, 1);
}

#[test]
fn test_uuid_redacted() {
    let r = make_redactor();
    let (out, stats) = r.redact_line(
        "session id a1b2c3d4-e5f6-7890-abcd-ef1234567890 created",
    );
    assert!(out.contains("[UUID_REDACTED]"));
    assert_eq!(stats.uuids_redacted, 1);
}

#[test]
fn test_password_field_redacted() {
    let r = make_redactor();
    let (out, stats) = r.redact_line("password=super_secret_123");
    assert!(out.contains("[PASSWORD_REDACTED]"));
    assert_eq!(stats.passwords_redacted, 1);
}

#[test]
fn test_hashed_style_produces_hex_placeholder() {
    let r = Redactor::new(RedactorConfig {
        style: ReplacementStyle::Hashed,
        skip_uuids: false,
        skip_ips: false,
        skip_emails: false,
    })
    .unwrap();
    let (out, stats) = r.redact_line("user foo@bar.com");
    assert!(stats.emails_redacted == 1);
    assert!(!out.contains("foo@bar.com"));
    assert!(out.contains('[') && out.contains(']'));
}

#[test]
fn test_ipv6_redacted() {
    let r = make_redactor();
    let (out, stats) = r.redact_line(
        "connection from 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    );
    assert!(out.contains("[IPV6_REDACTED]"));
    assert_eq!(stats.ipv6_redacted, 1);
}
