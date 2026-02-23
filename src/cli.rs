use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "log-anonymizer",
    version = "0.1.0",
    author = "Satyam Mistari",
    about = "High-speed PII redaction for log files",
    long_about = "Redacts emails, IPs, API keys, JWTs, and \
    passwords from log files using parallel processing. \
    Reads from stdin or file, writes to stdout or file."
)]
pub struct Cli {
    /// Input file path. If not provided, reads from stdin
    #[arg(short, long, value_name = "FILE")]
    pub input: Option<String>,

    /// Output file path. If not provided, writes to stdout
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<String>,

    /// Show redaction summary report after processing
    #[arg(short, long)]
    pub report: bool,

    /// Report output format
    #[arg(long, default_value = "pretty", value_parser = ["pretty", "json"])]
    pub report_format: String,

    /// Replacement style for redacted values
    #[arg(long, default_value = "tagged", value_parser = ["fixed", "tagged", "hashed"])]
    pub style: String,

    /// CI mode: exit with code 1 if any redactions found
    #[arg(long)]
    pub ci: bool,

    /// Skip redacting UUID values
    #[arg(long)]
    pub skip_uuids: bool,

    /// Skip redacting IP addresses
    #[arg(long)]
    pub skip_ips: bool,

    /// Skip redacting email addresses
    #[arg(long)]
    pub skip_emails: bool,

    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,

    /// Launch interactive TUI (terminal UI) for audit and diff
    #[arg(long)]
    pub tui: bool,

    /// Process all log files in a directory recursively
    #[arg(short = 'R', long)]
    pub recursive: bool,
}
