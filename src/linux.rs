//! Linux kernel hardening checks. Every path is resolved under `root`, so a
//! snapshot of /proc + /sys (or a container's view) can be audited offline.

use std::path::{Path, PathBuf};

use crate::kconfig;
use crate::model::Check;
use crate::report::Severity;

pub struct Ctx {
    pub root: PathBuf,
}

impl Ctx {
    fn path(&self, p: &str) -> PathBuf {
        self.root.join(p.trim_start_matches('/'))
    }

    fn read(&self, p: &str) -> Option<String> {
        std::fs::read_to_string(self.path(p))
            .ok()
            .map(|s| s.trim().to_string())
    }

    fn src(&self, p: &str) -> String {
        self.path(p).display().to_string()
    }
}

#[derive(Clone, Copy)]
enum Want {
    Eq(i64),
    AtLeast(i64),
}

struct Sysctl {
    id: &'static str,
    key: &'static str,
    want: Want,
    sev: Severity,
    why: &'static str,
}

const SYSCTLS: &[Sysctl] = &[
    Sysctl { id: "KSYS-001", key: "kernel.kptr_restrict", want: Want::AtLeast(1), sev: Severity::Medium,
        why: "Kernel pointers in /proc/kallsyms and friends leak the KASLR slide to unprivileged users." },
    Sysctl { id: "KSYS-002", key: "kernel.dmesg_restrict", want: Want::Eq(1), sev: Severity::Low,
        why: "The kernel log routinely contains addresses and driver state useful for exploitation." },
    Sysctl { id: "KSYS-003", key: "kernel.perf_event_paranoid", want: Want::AtLeast(2), sev: Severity::Medium,
        why: "perf_events is a recurring source of kernel CVEs and side channels for unprivileged users." },
    Sysctl { id: "KSYS-004", key: "kernel.unprivileged_bpf_disabled", want: Want::AtLeast(1), sev: Severity::High,
        why: "Unprivileged eBPF exposes the verifier/JIT — one of the most exploited kernel attack surfaces." },
    Sysctl { id: "KSYS-005", key: "net.core.bpf_jit_harden", want: Want::Eq(2), sev: Severity::Low,
        why: "Constant blinding in the BPF JIT for all users mitigates JIT spraying." },
    Sysctl { id: "KSYS-006", key: "kernel.yama.ptrace_scope", want: Want::AtLeast(1), sev: Severity::Medium,
        why: "With scope 0 any process can ptrace (read memory / inject into) every other process of the same user." },
    Sysctl { id: "KSYS-007", key: "kernel.kexec_load_disabled", want: Want::Eq(1), sev: Severity::Low,
        why: "kexec lets root replace the running kernel, bypassing Secure Boot and module signing." },
    Sysctl { id: "KSYS-008", key: "kernel.randomize_va_space", want: Want::Eq(2), sev: Severity::High,
        why: "Full userspace ASLR (stack, mmap, vdso and heap)." },
    Sysctl { id: "KSYS-009", key: "vm.mmap_min_addr", want: Want::AtLeast(65536), sev: Severity::High,
        why: "Low mappings turn kernel NULL-pointer dereferences into code execution." },
    Sysctl { id: "KSYS-010", key: "fs.protected_symlinks", want: Want::Eq(1), sev: Severity::Medium,
        why: "Blocks symlink races in world-writable sticky directories (/tmp)." },
    Sysctl { id: "KSYS-011", key: "fs.protected_hardlinks", want: Want::Eq(1), sev: Severity::Medium,
        why: "Blocks hardlinking files you do not own (classic setuid privilege escalation)." },
    Sysctl { id: "KSYS-012", key: "fs.protected_fifos", want: Want::Eq(2), sev: Severity::Low,
        why: "Prevents opening attacker-owned FIFOs in sticky directories." },
    Sysctl { id: "KSYS-013", key: "fs.protected_regular", want: Want::Eq(2), sev: Severity::Low,
        why: "Prevents O_CREAT on attacker-owned regular files in sticky directories." },
    Sysctl { id: "KSYS-014", key: "fs.suid_dumpable", want: Want::Eq(0), sev: Severity::Medium,
        why: "Core dumps of setuid programs can leak secrets (shadow hashes, keys)." },
    Sysctl { id: "KSYS-015", key: "kernel.sysrq", want: Want::Eq(0), sev: Severity::Low,
        why: "Magic SysRq gives anyone at the console kill/remount/reboot primitives." },
    Sysctl { id: "KSYS-016", key: "dev.tty.ldisc_autoload", want: Want::Eq(0), sev: Severity::Low,
        why: "Unprivileged users can autoload obscure TTY line-discipline modules (historic CVE source)." },
    Sysctl { id: "KSYS-017", key: "vm.unprivileged_userfaultfd", want: Want::Eq(0), sev: Severity::Low,
        why: "userfaultfd is used to win kernel race conditions reliably." },
    Sysctl { id: "KSYS-018", key: "kernel.io_uring_disabled", want: Want::AtLeast(1), sev: Severity::Low,
        why: "io_uring has had a high CVE rate; Google disabled it on ChromeOS/Android/production servers." },
    Sysctl { id: "KSYS-019", key: "kernel.unprivileged_userns_clone", want: Want::Eq(0), sev: Severity::Low,
        why: "Unprivileged user namespaces unlock kernel code paths (netfilter, mounts) to any user. May break rootless containers / browser sandboxes." },
];

fn sysctl_path(key: &str) -> String {
    format!("/proc/sys/{}", key.replace('.', "/"))
}

fn sysctl_checks(cx: &Ctx, out: &mut Vec<Check>) {
    for s in SYSCTLS {
        let p = sysctl_path(s.key);
        let mut c = Check::new(s.id, "sysctl", s.key, s.sev)
            .why(s.why)
            .source(cx.src(&p));
        let (expected, set) = match s.want {
            Want::Eq(n) => (format!("= {n}"), n),
            Want::AtLeast(n) => (format!(">= {n}"), n),
        };
        c = c.expected(expected).fix(format!(
            "sysctl -w {key}={set}  and persist it in /etc/sysctl.d/90-hardening.conf",
            key = s.key
        ));
        match cx.read(&p).and_then(|v| {
            v.split_whitespace()
                .next()
                .and_then(|n| n.parse::<i64>().ok())
        }) {
            Some(v) => {
                let pass = match s.want {
                    Want::Eq(n) => v == n,
                    Want::AtLeast(n) => v >= n,
                };
                out.push(c.observed(v.to_string()).pass(pass));
            }
            None => out.push(c.observed("absent").na()),
        }
    }
}

fn lockdown(cx: &Ctx, out: &mut Vec<Check>) {
    let p = "/sys/kernel/security/lockdown";
    let c = Check::new("KLCK-001", "lockdown", "Kernel lockdown", Severity::Medium)
        .why("Without lockdown, root can modify the running kernel (/dev/mem, kexec of unsigned kernels, unsigned modules, BPF writes to kernel memory, hibernation images) — erasing the user/kernel boundary.")
        .fix("Boot with lockdown=integrity (or confidentiality); distro kernels enable it automatically under Secure Boot.")
        .expected("integrity | confidentiality")
        .source(cx.src(p));
    match cx.read(p) {
        Some(v) => {
            let active = v
                .split_whitespace()
                .find(|w| w.starts_with('['))
                .map(|w| w.trim_matches(|c| c == '[' || c == ']').to_string())
                .unwrap_or_default();
            out.push(
                c.observed(active.clone())
                    .pass(active != "none" && !active.is_empty()),
            );
        }
        None => out.push(c.observed("lockdown LSM not present").pass(false)),
    }
}

fn module_signing(cx: &Ctx, out: &mut Vec<Check>) {
    let p = "/sys/module/module/parameters/sig_enforce";
    let c = Check::new("KMOD-001", "modules", "Module signature enforcement", Severity::Medium)
        .why("Unsigned kernel modules can be loaded by root — the standard path for rootkits.")
        .fix("Boot with module.sig_enforce=1 (implied by lockdown) and sign DKMS modules with an enrolled MOK.")
        .expected("Y")
        .source(cx.src(p));
    match cx.read(p) {
        Some(v) => out.push(c.observed(v.clone()).pass(v == "Y")),
        None => out.push(c.observed("CONFIG_MODULE_SIG off").pass(false)),
    }
    let p = "/proc/sys/kernel/modules_disabled";
    if let Some(v) = cx.read(p) {
        out.push(
            Check::new("KMOD-002", "modules", "Module loading locked after boot", Severity::Info)
                .why("kernel.modules_disabled=1 makes the module set immutable until reboot (one-way switch).")
                .fix("On fixed-function servers: sysctl -w kernel.modules_disabled=1 at the end of boot.")
                .observed(v.clone())
                .expected("1")
                .source(cx.src(p))
                .pass(v == "1"),
        );
    }
}

const TAINTS: &[(u32, char, &str, Severity, &str)] = &[
    (0, 'P', "proprietary module loaded", Severity::Info, "Closed-source module in the kernel; it cannot be audited."),
    (1, 'F', "module force-loaded", Severity::High, "A module was loaded with --force, skipping version/magic checks — typical for rootkits."),
    (3, 'R', "module force-unloaded", Severity::Medium, "A module was forcibly removed."),
    (4, 'M', "machine check exception", Severity::Medium, "The CPU reported a hardware error."),
    (5, 'B', "bad page referenced", Severity::Medium, "Memory corruption detected."),
    (7, 'D', "kernel oops/BUG occurred", Severity::Medium, "The kernel died at least once this boot; repeated oopses can indicate exploitation attempts."),
    (8, 'A', "ACPI table overridden", Severity::Medium, "Firmware ACPI tables were replaced at boot (initrd override), which can inject AML code."),
    (10, 'C', "staging driver loaded", Severity::Low, "Staging drivers are explicitly below kernel quality standards."),
    (12, 'O', "out-of-tree module loaded", Severity::Info, "Externally built module (DKMS, vendor driver)."),
    (13, 'E', "unsigned module loaded", Severity::High, "A module without a valid signature is running in the kernel."),
    (15, 'K', "kernel live-patched", Severity::Info, "Live patches are applied."),
];

fn taint(cx: &Ctx, out: &mut Vec<Check>) {
    let p = "/proc/sys/kernel/tainted";
    let Some(v) = cx.read(p).and_then(|v| v.parse::<u64>().ok()) else {
        return;
    };
    for (bit, flag, name, sev, why) in TAINTS {
        let set = v & (1 << bit) != 0;
        let id: &'static str = Box::leak(format!("KTNT-{flag}").into_boxed_str());
        out.push(
            Check::new(id, "taint", format!("Kernel taint '{flag}': {name}"), *sev)
                .why(*why)
                .fix("Identify the module via `cat /sys/module/*/taint` and dmesg; reboot into a clean state after removing it.")
                .observed(if set { "set" } else { "clear" })
                .expected("clear")
                .source(cx.src(p))
                .pass(!set),
        );
    }
}

fn cpu_vulns(cx: &Ctx, out: &mut Vec<Check>) -> Vec<(String, String)> {
    let dir = cx.path("/sys/devices/system/cpu/vulnerabilities");
    let mut rows = Vec::new();
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return rows;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().to_string_lossy().into_owned();
        let Ok(state) = std::fs::read_to_string(e.path()) else {
            continue;
        };
        let state = state.trim().to_string();
        rows.push((name.clone(), state.clone()));
        let vulnerable = state.starts_with("Vulnerable");
        let smt = state.contains("SMT vulnerable");
        // "Vulnerable: <partial mitigation>" (e.g. "Safe RET, no microcode")
        // is weaker than an outright unmitigated "Vulnerable".
        let sev = match (vulnerable, state.starts_with("Vulnerable:")) {
            (true, false) => Severity::High,
            (true, true) => Severity::Medium,
            _ => Severity::Low,
        };
        let id: &'static str =
            Box::leak(format!("KCPU-{}", name.to_ascii_uppercase()).into_boxed_str());
        out.push(
            Check::new(id, "cpu", format!("CPU vulnerability: {name}"), sev)
                .why(if vulnerable {
                    "The kernel reports this transient-execution vulnerability as unmitigated."
                } else {
                    "Mitigated, but SMT siblings still share the vulnerable structures."
                })
                .fix(if vulnerable {
                    "Update CPU microcode (intel-microcode/amd-ucode) and the kernel; remove mitigations=off / spectre_v2=off style parameters."
                } else {
                    "For hostile multi-tenant workloads disable SMT (nosmt or mitigations=auto,nosmt)."
                })
                .observed(state.clone())
                .expected("Not affected | Mitigation")
                .source(e.path().display().to_string())
                .pass(!vulnerable && !smt),
        );
    }
    rows
}

const BAD_CMDLINE: &[(&str, Severity, &str)] = &[
    (
        "mitigations=off",
        Severity::High,
        "disables every CPU vulnerability mitigation",
    ),
    (
        "nokaslr",
        Severity::High,
        "disables kernel address-space layout randomisation",
    ),
    (
        "nopti",
        Severity::High,
        "disables Meltdown page-table isolation",
    ),
    (
        "pti=off",
        Severity::High,
        "disables Meltdown page-table isolation",
    ),
    (
        "nospectre_v1",
        Severity::High,
        "disables Spectre v1 mitigations",
    ),
    (
        "nospectre_v2",
        Severity::High,
        "disables Spectre v2 mitigations",
    ),
    (
        "spectre_v2=off",
        Severity::High,
        "disables Spectre v2 mitigations",
    ),
    (
        "spec_store_bypass_disable=off",
        Severity::Medium,
        "disables SSB mitigation",
    ),
    (
        "tsx=on",
        Severity::Medium,
        "re-enables TSX (TAA / ZombieLoad v2 surface)",
    ),
    (
        "module.sig_enforce=0",
        Severity::Medium,
        "explicitly allows unsigned modules",
    ),
    (
        "lockdown=none",
        Severity::Medium,
        "explicitly disables kernel lockdown",
    ),
    ("selinux=0", Severity::Medium, "disables SELinux"),
    ("apparmor=0", Severity::Medium, "disables AppArmor"),
    ("enforcing=0", Severity::Medium, "boots SELinux permissive"),
    (
        "iommu=off",
        Severity::Medium,
        "disables the IOMMU (DMA attacks)",
    ),
    (
        "intel_iommu=off",
        Severity::Medium,
        "disables the Intel IOMMU (DMA attacks)",
    ),
    (
        "amd_iommu=off",
        Severity::Medium,
        "disables the AMD IOMMU (DMA attacks)",
    ),
    ("init_on_alloc=0", Severity::Low, "disables heap zeroing"),
    (
        "slub_debug=-",
        Severity::Low,
        "disables slab debugging/hardening",
    ),
    (
        "vsyscall=emulate",
        Severity::Low,
        "keeps a fixed-address vsyscall page",
    ),
];

const GOOD_CMDLINE: &[&str] = &[
    "init_on_alloc=1",
    "init_on_free=1",
    "slab_nomerge",
    "page_alloc.shuffle=1",
    "randomize_kstack_offset=on",
    "vsyscall=none",
    "debugfs=off",
    "lockdown=",
    "iommu.strict=1",
];

fn cmdline(cx: &Ctx, out: &mut Vec<Check>) -> Option<String> {
    let p = "/proc/cmdline";
    let line = cx.read(p)?;
    let args: Vec<&str> = line.split_whitespace().collect();
    for (i, (arg, sev, what)) in BAD_CMDLINE.iter().enumerate() {
        let present = args
            .iter()
            .any(|a| a == arg || (arg.ends_with('=') && a.starts_with(arg)));
        let id: &'static str = Box::leak(format!("KCMD-{:03}", i + 1).into_boxed_str());
        out.push(
            Check::new(id, "cmdline", format!("Kernel parameter `{arg}` not set"), *sev)
                .why(format!("`{arg}` {what}."))
                .fix(format!("Remove `{arg}` from GRUB_CMDLINE_LINUX (/etc/default/grub) or the systemd-boot entry, then regenerate the bootloader config."))
                .observed(if present { "present" } else { "absent" })
                .expected("absent")
                .source(cx.src(p))
                .pass(!present),
        );
    }
    let missing: Vec<&str> = GOOD_CMDLINE
        .iter()
        .filter(|g| !args.iter().any(|a| a.starts_with(*g)))
        .copied()
        .collect();
    out.push(
        Check::new(
            "KCMD-100",
            "cmdline",
            "Recommended hardening boot parameters",
            Severity::Info,
        )
        .why("Optional KSPP boot parameters that harden the allocator and debug interfaces.")
        .fix(format!("Consider adding: {}", missing.join(" ")))
        .observed(format!(
            "{} of {} present",
            GOOD_CMDLINE.len() - missing.len(),
            GOOD_CMDLINE.len()
        ))
        .expected("all")
        .source(cx.src(p))
        .pass(missing.is_empty()),
    );
    Some(line)
}

fn lsm(cx: &Ctx, out: &mut Vec<Check>) -> Option<String> {
    let p = "/sys/kernel/security/lsm";
    let list = cx.read(p)?;
    let mac = ["selinux", "apparmor", "smack", "tomoyo"];
    let active: Vec<&str> = list.split(',').filter(|l| mac.contains(l)).collect();
    out.push(
        Check::new("KLSM-001", "lsm", "Mandatory access control LSM active", Severity::Medium)
            .why("No SELinux/AppArmor/Smack/TOMOYO: a compromised service runs with its full DAC privileges.")
            .fix("Enable AppArmor (Debian/Ubuntu/SUSE) or SELinux (Fedora/RHEL) and ship profiles for network-facing services.")
            .observed(list.clone())
            .expected("selinux | apparmor | smack | tomoyo")
            .source(cx.src(p))
            .pass(!active.is_empty()),
    );
    out.push(
        Check::new("KLSM-002", "lsm", "Landlock available", Severity::Info)
            .why("Landlock lets unprivileged programs sandbox themselves.")
            .fix("Add landlock to the lsm= boot parameter / CONFIG_LSM.")
            .observed(if list.contains("landlock") {
                "yes"
            } else {
                "no"
            })
            .expected("yes")
            .source(cx.src(p))
            .pass(list.contains("landlock")),
    );
    if list.contains("selinux") {
        let p = "/sys/fs/selinux/enforce";
        if let Some(v) = cx.read(p) {
            out.push(
                Check::new("KLSM-003", "lsm", "SELinux enforcing", Severity::Medium)
                    .why("Permissive SELinux only logs denials.")
                    .fix("setenforce 1 and SELINUX=enforcing in /etc/selinux/config.")
                    .observed(if v == "1" { "enforcing" } else { "permissive" })
                    .expected("enforcing")
                    .source(cx.src(p))
                    .pass(v == "1"),
            );
        }
    }
    Some(list)
}

pub struct LinuxReport {
    pub release: Option<String>,
    pub arch: String,
    pub cmdline: Option<String>,
    pub lsm: Option<String>,
    pub cpu: Vec<(String, String)>,
    pub kconfig_source: Option<String>,
    pub wsl: bool,
}

pub fn audit(root: &Path, no_kconfig: bool) -> (Vec<Check>, LinuxReport) {
    let cx = Ctx {
        root: root.to_path_buf(),
    };
    let mut checks = Vec::new();
    let release = cx.read("/proc/sys/kernel/osrelease");
    let arch = cx
        .read("/proc/sys/kernel/arch")
        .unwrap_or_else(|| std::env::consts::ARCH.to_string());
    let wsl = release
        .as_deref()
        .is_some_and(|r| r.to_ascii_lowercase().contains("microsoft"));

    sysctl_checks(&cx, &mut checks);
    lockdown(&cx, &mut checks);
    module_signing(&cx, &mut checks);
    taint(&cx, &mut checks);
    let cpu = cpu_vulns(&cx, &mut checks);
    let cmd = cmdline(&cx, &mut checks);
    let lsm = lsm(&cx, &mut checks);

    let mut kconfig_source = None;
    if !no_kconfig {
        if let Some(cfg) = kconfig::load(root, release.as_deref()) {
            kconfig_source = Some(format!("{} ({} symbols)", cfg.source, cfg.len()));
            checks.extend(kconfig::checks(&cfg, &arch));
        }
    }

    (
        checks,
        LinuxReport {
            release,
            arch,
            cmdline: cmd,
            lsm,
            cpu,
            kconfig_source,
            wsl,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Status;

    fn fixture() -> PathBuf {
        let root = std::env::temp_dir().join(format!("krnlh3x-fx-{}", std::process::id()));
        let w = |p: &str, v: &str| {
            let f = root.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, v).unwrap();
        };
        w("proc/sys/kernel/kptr_restrict", "0\n");
        w("proc/sys/kernel/unprivileged_bpf_disabled", "2\n");
        w("proc/sys/kernel/randomize_va_space", "2\n");
        w(
            "proc/sys/kernel/tainted",
            &((1u64 << 13) | (1 << 12)).to_string(),
        );
        w(
            "proc/cmdline",
            "BOOT_IMAGE=/vmlinuz root=/dev/sda1 mitigations=off quiet\n",
        );
        w(
            "sys/kernel/security/lockdown",
            "[none] integrity confidentiality\n",
        );
        w(
            "sys/kernel/security/lsm",
            "lockdown,capability,landlock,yama,apparmor\n",
        );
        w("sys/module/module/parameters/sig_enforce", "N\n");
        w(
            "sys/devices/system/cpu/vulnerabilities/meltdown",
            "Not affected\n",
        );
        w(
            "sys/devices/system/cpu/vulnerabilities/spectre_v2",
            "Vulnerable\n",
        );
        w(
            "sys/devices/system/cpu/vulnerabilities/mds",
            "Mitigation: Clear CPU buffers; SMT vulnerable\n",
        );
        root
    }

    #[test]
    fn audits_fixture_tree() {
        let root = fixture();
        let (checks, rep) = audit(&root, true);
        let st = |id: &str| checks.iter().find(|c| c.id == id).map(|c| c.status);
        assert_eq!(st("KSYS-001"), Some(Status::Fail)); // kptr_restrict 0
        assert_eq!(st("KSYS-004"), Some(Status::Pass)); // bpf disabled 2
        assert_eq!(st("KSYS-008"), Some(Status::Pass));
        assert_eq!(st("KSYS-002"), Some(Status::Na)); // absent
        assert_eq!(st("KLCK-001"), Some(Status::Fail));
        assert_eq!(st("KMOD-001"), Some(Status::Fail));
        assert_eq!(st("KTNT-E"), Some(Status::Fail));
        assert_eq!(st("KTNT-O"), Some(Status::Fail));
        assert_eq!(st("KTNT-F"), Some(Status::Pass));
        assert_eq!(st("KCMD-001"), Some(Status::Fail)); // mitigations=off
        assert_eq!(st("KLSM-001"), Some(Status::Pass));
        assert_eq!(st("KCPU-SPECTRE_V2"), Some(Status::Fail));
        assert_eq!(st("KCPU-MELTDOWN"), Some(Status::Pass));
        let mds = checks.iter().find(|c| c.id == "KCPU-MDS").unwrap();
        assert_eq!((mds.status, mds.severity), (Status::Fail, Severity::Low));
        assert_eq!(rep.cpu.len(), 3);
        std::fs::remove_dir_all(root).ok();
    }
}
