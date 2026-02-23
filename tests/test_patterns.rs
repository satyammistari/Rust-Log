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
fn test_email_basic() {
    let r = make_redactor();
    let (out, stats) = r.redact_line("user john@example.com logged in");
    assert_eq!(out, "user [EMAIL_REDACTED] logged in");
    assert_eq!(stats.emails_redacted, 1);
}

#[test]
fn test_email_not_matched_in_version() {
    let r = make_redactor();
    let (out, stats) = r.redact_line("app version v1.2.3");
    assert_eq!(out, "app version v1.2.3");
    assert_eq!(stats.emails_redacted, 0);
}

#[test]
fn test_ipv4_basic() {
    let r = make_redactor();
    let (out, stats) = r.redact_line("request from 192.168.1.100 received");
    assert!(out.contains("[IPV4_REDACTED]"));
    assert_eq!(stats.ipv4_redacted, 1);
}

#[test]
fn test_jwt_redacted() {
    let r = make_redactor();
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.abc123def456";
    let (out, stats) = r.redact_line(&format!("Authorization: Bearer {}", jwt));
    assert!(out.contains("[JWT_REDACTED]"));
    assert_eq!(stats.jwts_redacted, 1);
}

#[test]
fn test_aws_access_key() {
    let r = make_redactor();
    let (out, stats) = r.redact_line("key=AKIAIOSFODNN7EXAMPLE config loaded");
    assert!(out.contains("[AWS_ACCESS_KEY_REDACTED]"));
    assert_eq!(stats.aws_keys_redacted, 1);
}

#[test]
fn test_multiple_patterns_same_line() {
    let r = make_redactor();
    let (out, stats) = r.redact_line(
        "user john@example.com from 10.0.0.1 authenticated",
    );
    assert!(out.contains("[EMAIL_REDACTED]"));
    assert!(out.contains("[IPV4_REDACTED]"));
    assert_eq!(stats.emails_redacted, 1);
    assert_eq!(stats.ipv4_redacted, 1);
}

#[test]
fn test_empty_line_unchanged() {
    let r = make_redactor();
    let (out, stats) = r.redact_line("");
    assert_eq!(out, "");
    assert_eq!(stats.total_redactions, 0);
}

#[test]
fn test_no_pii_line_unchanged() {
    let r = make_redactor();
    let line = "INFO: Server started on port 8080";
    let (out, stats) = r.redact_line(line);
    assert_eq!(out, line);
    assert_eq!(stats.total_redactions, 0);
}

#[test]
fn test_fixed_style() {
    let r = Redactor::new(RedactorConfig {
        style: ReplacementStyle::Fixed,
        skip_uuids: false,
        skip_ips: false,
        skip_emails: false,
    })
    .unwrap();
    let (out, _) = r.redact_line("email: test@example.com");
    assert!(out.contains("[REDACTED]"));
}

#[test]
fn test_skip_emails_flag() {
    let r = Redactor::new(RedactorConfig {
        style: ReplacementStyle::Tagged,
        skip_uuids: false,
        skip_ips: false,
        skip_emails: true,
    })
    .unwrap();
    let (out, stats) = r.redact_line("user@example.com authenticated");
    assert!(out.contains("user@example.com"));
    assert_eq!(stats.emails_redacted, 0);
}

#[test]
fn test_skip_ips_flag() {
    let r = Redactor::new(RedactorConfig {
        style: ReplacementStyle::Tagged,
        skip_uuids: false,
        skip_ips: true,
        skip_emails: false,
    })
    .unwrap();
    let (out, stats) = r.redact_line("request from 192.168.1.1");
    assert!(out.contains("192.168.1.1"));
    assert_eq!(stats.ipv4_redacted, 0);
}
