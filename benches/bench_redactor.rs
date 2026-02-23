use criterion::{black_box, criterion_group, criterion_main, Criterion};
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

fn bench_clean_line(c: &mut Criterion) {
    let r = make_redactor();
    let line = "INFO server started on port 8080 pid 12345";
    c.bench_function("clean_line_no_pii", |b| {
        b.iter(|| r.redact_line(black_box(line)))
    });
}

fn bench_line_with_email(c: &mut Criterion) {
    let r = make_redactor();
    let line = "user john.doe@company.com authenticated";
    c.bench_function("line_with_email", |b| {
        b.iter(|| r.redact_line(black_box(line)))
    });
}

fn bench_line_with_all_pii(c: &mut Criterion) {
    let r = make_redactor();
    let line = "user john@ex.com from 192.168.1.1 \
                token=eyJhbGciOiJIUzI1NiJ9\
                .eyJzdWIiOiJ1c2VyIn0.abc123 \
                key=AKIAIOSFODNN7EXAMPLE";
    c.bench_function("line_with_all_pii", |b| {
        b.iter(|| r.redact_line(black_box(line)))
    });
}

fn bench_100k_lines(c: &mut Criterion) {
    let r = make_redactor();
    let lines: Vec<String> = (0..100_000)
        .map(|i| {
            format!(
                "INFO user{}@company.com from 192.168.{}.{} \
             session-id={} authenticated",
                i,
                i % 256,
                i % 256,
                uuid::Uuid::new_v4()
            )
        })
        .collect();

    c.bench_function("parallel_100k_lines", |b| {
        use rayon::prelude::*;
        b.iter(|| {
            lines
                .par_iter()
                .map(|l| r.redact_line(black_box(l)))
                .collect::<Vec<_>>()
        })
    });
}

criterion_group!(
    benches,
    bench_clean_line,
    bench_line_with_email,
    bench_line_with_all_pii,
    bench_100k_lines,
);
criterion_main!(benches);
