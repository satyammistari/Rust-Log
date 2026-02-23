use colored::Colorize;
use serde::Serialize;

use crate::processor::ProcessResult;

#[derive(Serialize)]
struct JsonReport {
    emails_redacted: u64,
    ips_redacted: u64,
    jwts_redacted: u64,
    api_keys_redacted: u64,
    aws_keys_redacted: u64,
    credit_cards_redacted: u64,
    uuids_redacted: u64,
    passwords_redacted: u64,
    total_redactions: u64,
    lines_processed: u64,
    bytes_processed: u64,
    duration_ms: u64,
    throughput_mb_per_sec: f64,
}

pub fn print_report(result: &ProcessResult, format: &str, no_color: bool) {
    let stats = &result.stats;
    let mb = result.bytes_input as f64 / 1_048_576.0;
    let secs = result.duration_ms as f64 / 1000.0;
    let speed = if secs > 0.0 { mb / secs } else { 0.0 };

    if format == "json" {
        let report = JsonReport {
            emails_redacted: stats.emails_redacted,
            ips_redacted: stats.ipv4_redacted + stats.ipv6_redacted,
            jwts_redacted: stats.jwts_redacted,
            api_keys_redacted: stats.api_keys_redacted,
            aws_keys_redacted: stats.aws_keys_redacted,
            credit_cards_redacted: stats.credit_cards_redacted,
            uuids_redacted: stats.uuids_redacted,
            passwords_redacted: stats.passwords_redacted,
            total_redactions: stats.total_redactions,
            lines_processed: stats.lines_processed,
            bytes_processed: result.bytes_input,
            duration_ms: result.duration_ms,
            throughput_mb_per_sec: speed,
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
        return;
    }

    // Pretty print with colors
    eprintln!();
    eprintln!("{}", "Redaction Summary".bold());
    eprintln!("{}", "─".repeat(50));

    print_row("Emails", stats.emails_redacted, "[EMAIL_REDACTED]", no_color);
    print_row(
        "IPv4/IPv6",
        stats.ipv4_redacted + stats.ipv6_redacted,
        "[IPV4_REDACTED]",
        no_color,
    );
    print_row("JWTs", stats.jwts_redacted, "[JWT_REDACTED]", no_color);
    print_row(
        "API Keys",
        stats.api_keys_redacted,
        "[API_KEY_REDACTED]",
        no_color,
    );
    print_row(
        "AWS Keys",
        stats.aws_keys_redacted,
        "[AWS_KEY_REDACTED]",
        no_color,
    );
    print_row(
        "Credit Cards",
        stats.credit_cards_redacted,
        "[CREDIT_CARD_REDACTED]",
        no_color,
    );
    print_row("UUIDs", stats.uuids_redacted, "[UUID_REDACTED]", no_color);
    print_row(
        "Passwords",
        stats.passwords_redacted,
        "[PASSWORD_REDACTED]",
        no_color,
    );

    eprintln!("{}", "─".repeat(50));

    let total_str = format!("{} redactions", stats.total_redactions);
    if no_color {
        eprintln!("  Total           {}", total_str);
    } else {
        eprintln!("  Total           {}", total_str.yellow().bold());
    }

    eprintln!(
        "  Lines     {:>10}  processed",
        format_number(stats.lines_processed)
    );
    eprintln!("  Size      {:>8.1} MB  processed", mb);
    eprintln!("  Time      {:>8.1}  s  elapsed", secs);

    let speed_str = format!("{:.0} MB/s", speed);
    if no_color {
        eprintln!("  Speed     {:>10}  throughput", speed_str);
    } else {
        eprintln!(
            "  Speed     {:>10}  throughput",
            speed_str.green().bold()
        );
    }
    eprintln!();
}

fn print_row(
    label: &str,
    count: u64,
    replacement: &str,
    no_color: bool,
) {
    if count == 0 {
        return;
    }
    let count_str = format!("{:>6}", count);
    if no_color {
        eprintln!("  {:<16} {}  {}", label, count_str, replacement);
    } else {
        eprintln!(
            "  {:<16} {}  {}",
            label,
            count_str.red().bold(),
            replacement.dimmed()
        );
    }
}

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}
