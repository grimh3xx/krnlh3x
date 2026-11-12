//! krnlh3x — read-only kernel hardening auditor for Linux and Windows.
//!
//! Linux: KSPP sysctl and kconfig baselines, lockdown, module signing, taint
//! flags, CPU vulnerability state, boot parameters and LSMs.
//! Windows: code integrity / HVCI / test signing / kernel debugger, VBS and
//! Credential Guard, LSA protection, DEP and speculative-execution mitigations,
//! read from the kernel through NtQuerySystemInformation.
//! Nothing is changed — every finding comes with the command that fixes it.

mod kconfig;
mod linux;
mod model;
mod report;
#[cfg(windows)]
mod windows;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use anstream::println;
use clap::Parser;
use owo_colors::OwoColorize;
use serde::Serialize;

use model::{Check, Status};
use report::Severity;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const REPO: &str = "https://github.com/grimh3xx/krnlh3x";

#[derive(Parser)]
#[command(
    name = "krnlh3x",
    version,
    about = "Read-only kernel hardening auditor (Linux & Windows)"
)]
struct Cli {
    /// Audit a Linux tree rooted here (snapshot of /proc and /sys, container rootfs)
    #[arg(long, value_name = "DIR")]
    root: Option<PathBuf>,
    /// Skip the kernel build-config (KSPP kconfig) checks
    #[arg(long)]
    no_kconfig: bool,
    /// List passing and not-applicable checks too
    #[arg(long, short)]
    all: bool,
    /// Only run checks in these areas (comma list: sysctl,kconfig,cpu,cmdline,lsm,taint,lockdown,modules,...)
    #[arg(long, value_delimiter = ',')]
    area: Vec<String>,
    #[arg(long, conflicts_with = "sarif")]
    json: bool,
    #[arg(long)]
    sarif: bool,
    /// Lowest severity to report: info, low, medium, high, critical
    #[arg(long, default_value = "low", value_name = "LVL")]
    min_severity: String,
    /// Exit non-zero when the hardening score is below this value
    #[arg(long, value_name = "N")]
    min_score: Option<u32>,
    #[arg(long)]
    no_color: bool,
}

#[derive(Serialize, Default)]
struct Platform {
    os: &'static str,
    kernel: Option<String>,
    arch: String,
    cmdline: Option<String>,
    lsm: Option<String>,
    kconfig: Option<String>,
    cpu_vulnerabilities: BTreeMap<String, String>,
    wsl: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    code_integrity_options: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vbs_running: Option<bool>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.no_color {
        anstream::ColorChoice::Never.write_global();
    }
    let Some(min) = Severity::parse(&cli.min_severity) else {
        eprintln!("invalid --min-severity: {}", cli.min_severity);
        return ExitCode::from(64);
    };

    let (mut checks, platform) = collect(&cli);
    if !cli.area.is_empty() {
        checks.retain(|c| cli.area.iter().any(|a| a.eq_ignore_ascii_case(c.area)));
    }
    let score = model::score(&checks);
    let findings = report::filter_sort(model::findings(&checks), min);

    if cli.json {
        let v = serde_json::json!({
            "tool": "krnlh3x",
            "version": VERSION,
            "platform": platform,
            "score": score,
            "checks": checks,
            "findings": findings,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&v).expect("serializable")
        );
    } else if cli.sarif {
        let s = report::sarif("krnlh3x", VERSION, REPO, "kernel", &findings);
        println!(
            "{}",
            serde_json::to_string_pretty(&s).expect("serializable")
        );
    } else {
        banner();
        render_platform(&platform);
        render_checks(&checks, cli.all);
        report::print_findings(&findings);
        report::print_summary(&findings);
        let grade = match score.grade {
            "A" | "B" => score.grade.green().bold().to_string(),
            "C" => score.grade.yellow().bold().to_string(),
            _ => score.grade.red().bold().to_string(),
        };
        println!(
            "  {} hardening score {}/100  grade {}   ({} pass · {} fail · {} n/a)",
            "◆".cyan(),
            score.score.bold(),
            grade,
            score.passed,
            score.failed,
            score.not_applicable
        );
        println!();
    }

    let mut code = report::worst(&findings);
    if cli.min_score.is_some_and(|m| score.score < m) {
        code = code.max(5);
    }
    ExitCode::from(code)
}

#[cfg(not(windows))]
fn collect(cli: &Cli) -> (Vec<Check>, Platform) {
    linux_collect(cli)
}

#[cfg(windows)]
fn collect(cli: &Cli) -> (Vec<Check>, Platform) {
    if cli.root.is_some() {
        return linux_collect(cli);
    }
    let (checks, w) = windows::audit();
    let platform = Platform {
        os: "windows",
        kernel: w.build,
        arch: std::env::consts::ARCH.to_string(),
        code_integrity_options: w.ci_options.map(|v| format!("0x{v:x}")),
        vbs_running: w.vbs_running,
        ..Default::default()
    };
    let _ = (w.kva_flags, w.spec_flags);
    (checks, platform)
}

fn linux_collect(cli: &Cli) -> (Vec<Check>, Platform) {
    let root = cli.root.clone().unwrap_or_else(|| PathBuf::from("/"));
    let (checks, r) = linux::audit(&root, cli.no_kconfig);
    let platform = Platform {
        os: "linux",
        kernel: r.release,
        arch: r.arch,
        cmdline: r.cmdline,
        lsm: r.lsm,
        kconfig: r.kconfig_source,
        cpu_vulnerabilities: r.cpu.into_iter().collect(),
        wsl: r.wsl,
        ..Default::default()
    };
    (checks, platform)
}

fn banner() {
    println!();
    println!(
        "  {}{}  {}",
        "krnl".bold().cyan(),
        "h3x".bold().bright_blue(),
        format!("v{VERSION}").dimmed()
    );
    println!("  {}", "kernel hardening auditor · read-only".dimmed());
}

fn render_platform(p: &Platform) {
    report::section("platform");
    report::kv("os", p.os);
    report::kv("kernel", p.kernel.as_deref().unwrap_or("—"));
    report::kv("arch", &p.arch);
    if let Some(l) = &p.lsm {
        report::kv("LSMs", l);
    }
    if p.os == "linux" {
        report::kv(
            "kconfig",
            p.kconfig
                .as_deref()
                .unwrap_or("not found (/proc/config.gz, /boot/config-*)"),
        );
    }
    if let Some(ci) = &p.code_integrity_options {
        report::kv("CI options", ci);
    }
    if p.wsl {
        report::kv(
            "note",
            "WSL2 kernel — Microsoft-built, host hardening lives in Windows (run krnlh3x.exe)"
                .yellow(),
        );
    }
}

fn render_checks(checks: &[Check], all: bool) {
    let mut areas: Vec<&str> = checks.iter().map(|c| c.area).collect();
    areas.dedup();
    let mut seen = std::collections::HashSet::new();
    areas.retain(|a| seen.insert(*a));

    let idw = checks
        .iter()
        .filter(|c| all || c.status == Status::Fail)
        .map(|c| c.id.len())
        .max()
        .unwrap_or(8)
        .max(8);
    report::section("checks");
    for area in areas {
        let in_area: Vec<&Check> = checks.iter().filter(|c| c.area == area).collect();
        let pass = in_area.iter().filter(|c| c.status == Status::Pass).count();
        let fail = in_area.iter().filter(|c| c.status == Status::Fail).count();
        let applicable = pass + fail;
        let bar = meter(pass, applicable);
        println!(
            "    {:<15} {} {:>3}/{:<3} {}",
            area.bold(),
            bar,
            pass,
            applicable,
            if fail > 0 {
                format!("{fail} failing").red().to_string()
            } else {
                "ok".green().to_string()
            }
        );
        for c in in_area {
            let show = all || c.status == Status::Fail;
            if !show {
                continue;
            }
            let mark = match c.status {
                Status::Pass => "✓".green().to_string(),
                Status::Fail => "✗".red().to_string(),
                Status::Na => "·".dimmed().to_string(),
            };
            let name = if c.name.chars().count() > 44 {
                format!("{}…", c.name.chars().take(43).collect::<String>())
            } else {
                c.name.clone()
            };
            let observed: String = c.observed.chars().take(48).collect();
            println!(
                "      {mark} {:<idw$} {:<45} {}",
                c.id.dimmed(),
                name,
                observed.dimmed()
            );
        }
    }
}

fn meter(pass: usize, total: usize) -> String {
    const W: usize = 16;
    if total == 0 {
        return "·".repeat(W).dimmed().to_string();
    }
    let filled = (pass * W + total / 2) / total;
    let s = format!("{}{}", "█".repeat(filled), "░".repeat(W - filled));
    match pass * 100 / total {
        90.. => s.green().to_string(),
        60..=89 => s.yellow().to_string(),
        _ => s.red().to_string(),
    }
}
