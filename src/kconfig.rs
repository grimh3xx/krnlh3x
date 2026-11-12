//! Kernel build configuration audit against the Kernel Self Protection
//! Project (KSPP) recommendations. Reads `/proc/config.gz` (gunzipped in pure
//! Rust) or `/boot/config-<release>`.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::model::Check;
use crate::report::Severity;

pub struct Config {
    pub source: String,
    values: HashMap<String, String>,
}

impl Config {
    pub fn parse(text: &str, source: impl Into<String>) -> Self {
        let mut values = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("# ") {
                if let Some(name) = rest.strip_suffix(" is not set") {
                    values.insert(name.to_string(), "n".to_string());
                }
            } else if let Some((k, v)) = line.split_once('=') {
                if k.starts_with("CONFIG_") {
                    values.insert(k.to_string(), v.trim_matches('"').to_string());
                }
            }
        }
        Self {
            source: source.into(),
            values,
        }
    }

    /// "n" for explicitly unset and for absent symbols (Kconfig semantics).
    pub fn get(&self, key: &str) -> &str {
        self.values.get(key).map_or("n", String::as_str)
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }
}

pub fn load(root: &Path, release: Option<&str>) -> Option<Config> {
    let gz = root.join("proc/config.gz");
    if let Ok(f) = std::fs::File::open(&gz) {
        let mut text = String::new();
        if flate2::read::GzDecoder::new(f)
            .read_to_string(&mut text)
            .is_ok()
        {
            return Some(Config::parse(&text, gz.display().to_string()));
        }
    }
    let candidates: Vec<PathBuf> = release
        .map(|r| {
            vec![
                root.join(format!("boot/config-{r}")),
                root.join(format!("lib/modules/{r}/build/.config")),
            ]
        })
        .unwrap_or_default();
    candidates.into_iter().find_map(|p| {
        std::fs::read_to_string(&p)
            .ok()
            .map(|t| Config::parse(&t, p.display().to_string()))
    })
}

enum Want {
    Y,
    N,
    AtLeast(i64),
}

struct Rule {
    key: &'static str,
    want: Want,
    sev: Severity,
    why: &'static str,
    /// Only meaningful on these architectures (empty = all).
    arch: &'static [&'static str],
}

const X86: &[&str] = &["x86_64", "x86"];

const RULES: &[Rule] = &[
    Rule {
        key: "CONFIG_STRICT_KERNEL_RWX",
        want: Want::Y,
        sev: Severity::High,
        arch: &[],
        why: "kernel text read-only and data non-executable",
    },
    Rule {
        key: "CONFIG_STRICT_MODULE_RWX",
        want: Want::Y,
        sev: Severity::High,
        arch: &[],
        why: "same W^X guarantee for loadable modules",
    },
    Rule {
        key: "CONFIG_STACKPROTECTOR_STRONG",
        want: Want::Y,
        sev: Severity::High,
        arch: &[],
        why: "stack canaries on every function with local arrays/addresses",
    },
    Rule {
        key: "CONFIG_RANDOMIZE_BASE",
        want: Want::Y,
        sev: Severity::High,
        arch: &[],
        why: "KASLR",
    },
    Rule {
        key: "CONFIG_VMAP_STACK",
        want: Want::Y,
        sev: Severity::High,
        arch: &[],
        why: "guard pages around kernel stacks stop stack overflows into adjacent memory",
    },
    Rule {
        key: "CONFIG_STRICT_DEVMEM",
        want: Want::Y,
        sev: Severity::High,
        arch: &[],
        why: "/dev/mem cannot reach kernel RAM",
    },
    Rule {
        key: "CONFIG_HARDENED_USERCOPY",
        want: Want::Y,
        sev: Severity::Medium,
        arch: &[],
        why: "bounds-checks copy_to/from_user against slab and stack objects",
    },
    Rule {
        key: "CONFIG_FORTIFY_SOURCE",
        want: Want::Y,
        sev: Severity::Medium,
        arch: &[],
        why: "compile/run-time bounds checks on mem*/str* helpers",
    },
    Rule {
        key: "CONFIG_IO_STRICT_DEVMEM",
        want: Want::Y,
        sev: Severity::Medium,
        arch: &[],
        why: "/dev/mem cannot touch I/O regions claimed by drivers",
    },
    Rule {
        key: "CONFIG_SLAB_FREELIST_HARDENED",
        want: Want::Y,
        sev: Severity::Medium,
        arch: &[],
        why: "obfuscated slab freelist pointers defeat freelist overwrite exploits",
    },
    Rule {
        key: "CONFIG_SLAB_FREELIST_RANDOM",
        want: Want::Y,
        sev: Severity::Medium,
        arch: &[],
        why: "randomised slab allocation order",
    },
    Rule {
        key: "CONFIG_SECURITY_LOCKDOWN_LSM",
        want: Want::Y,
        sev: Severity::Medium,
        arch: &[],
        why: "kernel lockdown (integrity/confidentiality) is available",
    },
    Rule {
        key: "CONFIG_MODULE_SIG",
        want: Want::Y,
        sev: Severity::Medium,
        arch: &[],
        why: "module signature verification is compiled in",
    },
    Rule {
        key: "CONFIG_SECCOMP_FILTER",
        want: Want::Y,
        sev: Severity::Medium,
        arch: &[],
        why: "seccomp-bpf sandboxing for userspace",
    },
    Rule {
        key: "CONFIG_PAGE_TABLE_ISOLATION",
        want: Want::Y,
        sev: Severity::Medium,
        arch: X86,
        why: "Meltdown mitigation (KPTI)",
    },
    Rule {
        key: "CONFIG_RETPOLINE",
        want: Want::Y,
        sev: Severity::Medium,
        arch: X86,
        why: "Spectre v2 mitigation (also CONFIG_MITIGATION_RETPOLINE on 6.9+)",
    },
    Rule {
        key: "CONFIG_INIT_ON_ALLOC_DEFAULT_ON",
        want: Want::Y,
        sev: Severity::Low,
        arch: &[],
        why: "zero heap memory on allocation (info leaks / uninitialised use)",
    },
    Rule {
        key: "CONFIG_INIT_STACK_ALL_ZERO",
        want: Want::Y,
        sev: Severity::Low,
        arch: &[],
        why: "zero-initialise stack variables",
    },
    Rule {
        key: "CONFIG_SHUFFLE_PAGE_ALLOCATOR",
        want: Want::Y,
        sev: Severity::Low,
        arch: &[],
        why: "randomised page allocator free lists",
    },
    Rule {
        key: "CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT",
        want: Want::Y,
        sev: Severity::Low,
        arch: &[],
        why: "per-syscall kernel stack offset randomisation",
    },
    Rule {
        key: "CONFIG_SCHED_STACK_END_CHECK",
        want: Want::Y,
        sev: Severity::Low,
        arch: &[],
        why: "detects kernel stack overruns at schedule()",
    },
    Rule {
        key: "CONFIG_BUG_ON_DATA_CORRUPTION",
        want: Want::Y,
        sev: Severity::Low,
        arch: &[],
        why: "BUG on detected list/data corruption instead of continuing",
    },
    Rule {
        key: "CONFIG_LIST_HARDENED",
        want: Want::Y,
        sev: Severity::Low,
        arch: &[],
        why: "linked-list integrity checks (6.6+)",
    },
    Rule {
        key: "CONFIG_DEBUG_WX",
        want: Want::Y,
        sev: Severity::Low,
        arch: &[],
        why: "warns at boot about W+X kernel mappings",
    },
    Rule {
        key: "CONFIG_SECURITY_DMESG_RESTRICT",
        want: Want::Y,
        sev: Severity::Low,
        arch: &[],
        why: "dmesg restricted to CAP_SYSLOG by default",
    },
    Rule {
        key: "CONFIG_SECURITY_YAMA",
        want: Want::Y,
        sev: Severity::Low,
        arch: &[],
        why: "Yama ptrace scope restrictions",
    },
    Rule {
        key: "CONFIG_LEGACY_VSYSCALL_NONE",
        want: Want::Y,
        sev: Severity::Low,
        arch: X86,
        why: "no fixed-address vsyscall page (ROP gadget source)",
    },
    Rule {
        key: "CONFIG_X86_KERNEL_IBT",
        want: Want::Y,
        sev: Severity::Low,
        arch: X86,
        why: "Intel CET indirect-branch tracking in the kernel",
    },
    Rule {
        key: "CONFIG_DEVMEM",
        want: Want::N,
        sev: Severity::Low,
        arch: &[],
        why: "/dev/mem not available at all",
    },
    Rule {
        key: "CONFIG_DEVKMEM",
        want: Want::N,
        sev: Severity::High,
        arch: &[],
        why: "/dev/kmem gives direct kernel memory write access",
    },
    Rule {
        key: "CONFIG_PROC_KCORE",
        want: Want::N,
        sev: Severity::Low,
        arch: &[],
        why: "/proc/kcore exposes kernel memory to root",
    },
    Rule {
        key: "CONFIG_COMPAT_BRK",
        want: Want::N,
        sev: Severity::Low,
        arch: &[],
        why: "keeps heap (brk) randomisation enabled",
    },
    Rule {
        key: "CONFIG_ACPI_CUSTOM_METHOD",
        want: Want::N,
        sev: Severity::High,
        arch: &[],
        why: "debugfs interface that writes arbitrary kernel memory via ACPI",
    },
    Rule {
        key: "CONFIG_HIBERNATION",
        want: Want::N,
        sev: Severity::Info,
        arch: &[],
        why: "hibernation images can be used to tamper with kernel state offline",
    },
    Rule {
        key: "CONFIG_LEGACY_TIOCSTI",
        want: Want::N,
        sev: Severity::Low,
        arch: &[],
        why: "TIOCSTI terminal injection",
    },
    Rule {
        key: "CONFIG_SECURITY_SELINUX_DEVELOP",
        want: Want::N,
        sev: Severity::Info,
        arch: &[],
        why: "SELinux can be booted permissive",
    },
    Rule {
        key: "CONFIG_DEFAULT_MMAP_MIN_ADDR",
        want: Want::AtLeast(65536),
        sev: Severity::Medium,
        arch: &[],
        why: "NULL-dereference exploitation needs low mappings",
    },
];

pub fn checks(cfg: &Config, arch: &str) -> Vec<Check> {
    RULES
        .iter()
        .map(|r| {
            let got = cfg.get(r.key);
            let id: &'static str = Box::leak(format!("KCFG-{}", &r.key[7..]).into_boxed_str());
            let mut c = Check::new(id, "kconfig", r.key, r.sev)
                .why(r.why)
                .source(cfg.source.clone())
                .observed(got.to_string());
            if !r.arch.is_empty() && !r.arch.contains(&arch) {
                return c.na();
            }
            // Renamed in 6.9: CONFIG_RETPOLINE -> CONFIG_MITIGATION_RETPOLINE etc.
            let alt = r
                .key
                .strip_prefix("CONFIG_")
                .map(|k| format!("CONFIG_MITIGATION_{k}"));
            let got_alt = alt.as_deref().map(|a| cfg.get(a)).unwrap_or("n");
            let (ok, expected) = match r.want {
                Want::Y => (got == "y" || got_alt == "y", "y".to_string()),
                Want::N => (got == "n", "not set".to_string()),
                Want::AtLeast(n) => (parse_num(got).is_some_and(|v| v >= n), format!(">= {n}")),
            };
            c = c.expected(expected).pass(ok);
            c.fix = format!(
                "Rebuild with {} (or use a distro hardened kernel flavour).",
                match r.want {
                    Want::N => format!("# {} is not set", r.key),
                    Want::AtLeast(n) => format!("{}={n}", r.key),
                    _ => format!("{}=y", r.key),
                }
            );
            c
        })
        .collect()
}

fn parse_num(s: &str) -> Option<i64> {
    s.strip_prefix("0x")
        .map_or_else(|| s.parse().ok(), |h| i64::from_str_radix(h, 16).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Status;

    #[test]
    fn parses_set_unset_and_absent() {
        let c = Config::parse(
            "CONFIG_A=y\n# CONFIG_B is not set\nCONFIG_C=\"str\"\nCONFIG_D=4096\n",
            "t",
        );
        assert_eq!(c.get("CONFIG_A"), "y");
        assert_eq!(c.get("CONFIG_B"), "n");
        assert_eq!(c.get("CONFIG_C"), "str");
        assert_eq!(c.get("CONFIG_ZZZ"), "n");
        assert_eq!(c.len(), 4);
    }

    #[test]
    fn rules_evaluate() {
        let c = Config::parse(
            "CONFIG_STRICT_KERNEL_RWX=y\nCONFIG_DEVKMEM=y\nCONFIG_DEFAULT_MMAP_MIN_ADDR=4096\nCONFIG_MITIGATION_RETPOLINE=y\n",
            "t",
        );
        let all = checks(&c, "x86_64");
        let by = |k: &str| all.iter().find(|c| c.name == k).unwrap().status;
        assert_eq!(by("CONFIG_STRICT_KERNEL_RWX"), Status::Pass);
        assert_eq!(by("CONFIG_DEVKMEM"), Status::Fail);
        assert_eq!(by("CONFIG_DEFAULT_MMAP_MIN_ADDR"), Status::Fail);
        assert_eq!(by("CONFIG_RETPOLINE"), Status::Pass);
        assert_eq!(by("CONFIG_PROC_KCORE"), Status::Pass);
        let arm = checks(&c, "aarch64");
        assert_eq!(
            arm.iter()
                .find(|c| c.name == "CONFIG_RETPOLINE")
                .unwrap()
                .status,
            Status::Na
        );
    }
}
