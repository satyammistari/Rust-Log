mod cli;

use std::path::Path;
use std::process;

use clap::Parser;
use cli::Cli;
use log_anonymizer::redactor::{Redactor, RedactorConfig, ReplacementStyle};

fn main() {
    let cli = Cli::parse();

    // Build redactor config from CLI flags
    let config = RedactorConfig {
        style: ReplacementStyle::from_str(&cli.style),
        skip_uuids: cli.skip_uuids,
        skip_ips: cli.skip_ips,
        skip_emails: cli.skip_emails,
    };

    // Build redactor — compiles all regexes here, once
    let redactor = match Redactor::new(config) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error initializing redactor: {}", e);
            process::exit(2);
        }
    };

    // Route to correct processor based on flags
    let result = if cli.recursive {
        // Directory mode
        let input_dir = cli.input.as_deref().unwrap_or(".");
        log_anonymizer::processor::process_directory(
            Path::new(input_dir),
            cli.output.as_deref().map(Path::new),
            &redactor,
        )
    } else if let Some(ref input_path) = cli.input {
        // File mode
        log_anonymizer::processor::process_file(
            Path::new(input_path),
            cli.output.as_deref().map(Path::new),
            &redactor,
        )
    } else {
        // Stdin mode
        log_anonymizer::processor::process_stdin(&redactor)
    };

    match result {
        Ok(process_result) => {
            // Print report if requested
            if cli.report {
                log_anonymizer::reporter::print_report(
                    &process_result,
                    &cli.report_format,
                    cli.no_color,
                );
            }

            // CI mode: exit 1 if any redactions found
            if cli.ci && process_result.stats.total_redactions > 0 {
                eprintln!(
                    "CI: {} redactions found — failing build",
                    process_result.stats.total_redactions
                );
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(2);
        }
    }
}
