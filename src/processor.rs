use std::fs::File;
use std::io::{self, BufRead, BufWriter, Write};
use std::path::Path;
use std::time::Instant;

use memmap2::Mmap;
use rayon::prelude::*;

use crate::error::Result;
use crate::redactor::{Redactor, RedactionStats};

pub struct ProcessResult {
    pub stats: RedactionStats,
    pub duration_ms: u64,
    pub bytes_input: u64,
}

pub fn process_file(
    input_path: &Path,
    output_path: Option<&Path>,
    redactor: &Redactor,
) -> Result<ProcessResult> {
    let start = Instant::now();

    // Open and memory-map the input file
    let file = File::open(input_path)?;
    let bytes = file.metadata()?.len();
    let mmap = unsafe { Mmap::map(&file)? };

    // Parse as UTF-8 string slice — zero copy
    let content = std::str::from_utf8(&mmap)?;

    // Process lines in parallel using rayon
    // Each line is independent — no shared mutable state
    let line_results: Vec<(String, RedactionStats)> = content
        .par_lines()
        .map(|line| redactor.redact_line(line))
        .collect();

    // Merge all stats
    let mut total_stats = RedactionStats::default();
    let mut output_lines = Vec::with_capacity(line_results.len());

    for (clean_line, line_stats) in line_results {
        output_lines.push(clean_line);
        total_stats.merge(&line_stats);
    }

    total_stats.lines_processed = output_lines.len() as u64;

    // Write output
    let clean_content = output_lines.join("\n");

    match output_path {
        Some(path) => {
            let out_file = File::create(path)?;
            let mut writer = BufWriter::new(out_file);
            writer.write_all(clean_content.as_bytes())?;
        }
        None => {
            // Write to stdout
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            handle.write_all(clean_content.as_bytes())?;
            writeln!(handle)?;
        }
    }

    Ok(ProcessResult {
        stats: total_stats,
        duration_ms: start.elapsed().as_millis() as u64,
        bytes_input: bytes,
    })
}

pub fn process_stdin(redactor: &Redactor) -> Result<ProcessResult> {
    let start = Instant::now();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    let mut total_stats = RedactionStats::default();
    let mut bytes_read: u64 = 0;

    for line in stdin.lock().lines() {
        let line = line?;
        bytes_read += line.len() as u64 + 1;

        let (clean, stats) = redactor.redact_line(&line);
        total_stats.merge(&stats);

        writeln!(out, "{}", clean)?;
    }

    total_stats.lines_processed = total_stats.lines_processed.max(1);

    Ok(ProcessResult {
        stats: total_stats,
        duration_ms: start.elapsed().as_millis() as u64,
        bytes_input: bytes_read,
    })
}

pub fn process_directory(
    dir_path: &Path,
    output_dir: Option<&Path>,
    redactor: &Redactor,
) -> Result<ProcessResult> {
    use walkdir::WalkDir;

    let mut total_result = ProcessResult {
        stats: RedactionStats::default(),
        duration_ms: 0,
        bytes_input: 0,
    };

    for entry in WalkDir::new(dir_path)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            e.path()
                .extension()
                .map_or(false, |ext| ext == "log" || ext == "txt")
        })
    {
        let output_path = output_dir.map(|d| d.join(entry.file_name()));

        let result = process_file(
            entry.path(),
            output_path.as_deref(),
            redactor,
        )?;

        total_result.stats.merge(&result.stats);
        total_result.duration_ms += result.duration_ms;
        total_result.bytes_input += result.bytes_input;
    }

    Ok(total_result)
}
