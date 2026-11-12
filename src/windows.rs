//! Windows kernel hardening checks. Running state comes straight from the
//! kernel via NtQuerySystemInformation (code integrity options, isolated user
//! mode, KVA shadow, speculation control) — the same sources msinfo32 and
//! Microsoft's SpeculationControl module use — with registry policy as context.

use std::ffi::c_void;

use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Registry::{
    RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDEPPolicy;

use crate::model::Check;
use crate::report::Severity;

const SYSTEM_KERNEL_DEBUGGER_INFORMATION: i32 = 35;
const SYSTEM_CODE_INTEGRITY_INFORMATION: i32 = 103;
const SYSTEM_ISOLATED_USER_MODE_INFORMATION: i32 = 165;
const SYSTEM_KERNEL_VA_SHADOW_INFORMATION: i32 = 196;
const SYSTEM_SPECULATION_CONTROL_INFORMATION: i32 = 201;

// CODEINTEGRITY_OPTION_*
const CI_ENABLED: u32 = 0x01;
const CI_TESTSIGN: u32 = 0x02;
const CI_UMCI_ENABLED: u32 = 0x04;
const CI_DEBUGMODE_ENABLED: u32 = 0x80;
const CI_HVCI_KMCI_ENABLED: u32 = 0x400;
const CI_HVCI_KMCI_AUDITMODE: u32 = 0x800;
const CI_HVCI_KMCI_STRICTMODE: u32 = 0x1000;

// SYSTEM_KERNEL_VA_SHADOW_INFORMATION.Flags
const KVA_ENABLED: u32 = 0x01;
const KVA_REQUIRED: u32 = 0x10;
const KVA_REQUIRED_AVAILABLE: u32 = 0x20;
const L1TF_MITIGATION_PRESENT: u32 = 0x2000;

// SYSTEM_SPECULATION_CONTROL_INFORMATION.Flags
const SC_BPB_ENABLED: u32 = 0x01;
const SC_BPB_DISABLED_POLICY: u32 = 0x02;
const SC_BPB_DISABLED_NO_HW: u32 = 0x04;
const SC_SMEP_PRESENT: u32 = 0x80;
const SC_SSBD_SYSTEM_WIDE: u32 = 0x400;
const SC_SSBD_REQUIRED: u32 = 0x1000;
const SC_RETPOLINE: u32 = 0x4000;
const SC_ENHANCED_IBRS: u32 = 0x10000;
const SC_MDS_HW_PROTECTED: u32 = 0x0100_0000;
const SC_MBCLEAR_ENABLED: u32 = 0x0200_0000;
const SC_MBCLEAR_REPORTED: u32 = 0x0400_0000;

fn query(class: i32, buf: &mut [u8]) -> bool {
    let mut ret = 0u32;
    // SAFETY: buf is a valid, writable buffer of the length passed.
    let st = unsafe {
        NtQuerySystemInformation(
            class,
            buf.as_mut_ptr().cast::<c_void>(),
            buf.len() as u32,
            &mut ret,
        )
    };
    st >= 0
}

fn query_u32(class: i32) -> Option<u32> {
    // Newer builds grow these structs; try the larger size first.
    for len in [8usize, 4] {
        let mut b = vec![0u8; len];
        if query(class, &mut b) {
            return Some(u32::from_le_bytes(b[..4].try_into().ok()?));
        }
    }
    None
}

fn code_integrity() -> Option<u32> {
    let mut b = [0u8; 8];
    b[..4].copy_from_slice(&8u32.to_le_bytes()); // Length is an input field
    query(SYSTEM_CODE_INTEGRITY_INFORMATION, &mut b)
        .then(|| u32::from_le_bytes(b[4..8].try_into().unwrap()))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

pub fn reg_dword(key: &str, value: &str) -> Option<u32> {
    let (k, v) = (wide(key), wide(value));
    let mut data = 0u32;
    let mut size = 4u32;
    // SAFETY: data/size describe a 4-byte buffer; strings are NUL-terminated.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            k.as_ptr(),
            v.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&mut data as *mut u32).cast(),
            &mut size,
        )
    };
    (rc == 0).then_some(data)
}

pub fn reg_string(key: &str, value: &str) -> Option<String> {
    let (k, v) = (wide(key), wide(value));
    let mut buf = vec![0u16; 512];
    let mut size = (buf.len() * 2) as u32;
    // SAFETY: buf is writable for `size` bytes.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            k.as_ptr(),
            v.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if rc != 0 {
        return None;
    }
    buf.truncate((size as usize / 2).saturating_sub(1));
    Some(String::from_utf16_lossy(&buf))
}

fn process_running(name: &str) -> bool {
    // SAFETY: standard Toolhelp enumeration; the snapshot handle is closed.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return false;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = false;
        let mut ok = Process32FirstW(snap, &mut e) != 0;
        while ok {
            let len = e
                .szExeFile
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(e.szExeFile.len());
            if String::from_utf16_lossy(&e.szExeFile[..len]).eq_ignore_ascii_case(name) {
                found = true;
                break;
            }
            ok = Process32NextW(snap, &mut e) != 0;
        }
        CloseHandle(snap);
        found
    }
}

const LSA: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
const DG: &str = r"SYSTEM\CurrentControlSet\Control\DeviceGuard";
const MM: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management";
const CI_CONFIG: &str = r"SYSTEM\CurrentControlSet\Control\CI\Config";
const WDIGEST: &str = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";

fn hex(v: u32) -> String {
    format!("0x{v:x}")
}

pub struct WinReport {
    pub build: Option<String>,
    pub ci_options: Option<u32>,
    pub vbs_running: Option<bool>,
    pub kva_flags: Option<u32>,
    pub spec_flags: Option<u32>,
}

pub fn audit() -> (Vec<Check>, WinReport) {
    let mut out = Vec::new();
    let nt = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let build = match (
        reg_string(nt, "ProductName"),
        reg_string(nt, "DisplayVersion"),
        reg_string(nt, "CurrentBuild"),
    ) {
        (Some(p), d, Some(b)) => Some(format!("{p} {} (build {b})", d.unwrap_or_default())),
        _ => None,
    };

    // --- code integrity --------------------------------------------------
    let ci = code_integrity();
    let src_ci = "ntdll!NtQuerySystemInformation(SystemCodeIntegrityInformation)";
    let flag = |f: u32| ci.map(|v| v & f != 0);
    let push_ci = |out: &mut Vec<Check>, c: Check, v: Option<bool>| {
        out.push(match v {
            Some(b) => c.pass(b),
            None => c.observed("unavailable").na(),
        })
    };
    let obs = ci.map(hex).unwrap_or_default();
    push_ci(&mut out, Check::new("WCI-001", "code integrity", "Driver signature enforcement (DSE) active", Severity::Critical)
        .why("With code integrity off the kernel loads unsigned drivers — any administrator can run arbitrary ring-0 code.")
        .fix("bcdedit /set nointegritychecks off ; reboot. Investigate why it was disabled.")
        .observed(obs.clone()).expected("CODEINTEGRITY_OPTION_ENABLED").source(src_ci), flag(CI_ENABLED));
    push_ci(
        &mut out,
        Check::new(
            "WCI-002",
            "code integrity",
            "Test signing disabled",
            Severity::High,
        )
        .why("TESTSIGNING accepts drivers signed by any self-made certificate.")
        .fix("bcdedit /set testsigning off ; reboot.")
        .observed(obs.clone())
        .expected("TESTSIGN clear")
        .source(src_ci),
        flag(CI_TESTSIGN).map(|b| !b),
    );
    let mut dbg = [0u8; 2];
    let kd = query(SYSTEM_KERNEL_DEBUGGER_INFORMATION, &mut dbg).then_some(dbg[0] != 0);
    let debug = match (flag(CI_DEBUGMODE_ENABLED), kd) {
        (Some(a), Some(b)) => Some(a || b),
        (a, b) => a.or(b),
    };
    push_ci(&mut out, Check::new("WCI-003", "code integrity", "Kernel debugging disabled", Severity::High)
        .why("A boot-enabled kernel debugger can read/patch kernel memory and disables PatchGuard-style protections.")
        .fix("bcdedit /debug off ; bcdedit /set {current} bootdebug off ; reboot.")
        .observed(format!("debugmode={:?} kd={:?}", flag(CI_DEBUGMODE_ENABLED), kd)).expected("off").source(src_ci), debug.map(|b| !b));
    push_ci(&mut out, Check::new("WCI-004", "code integrity", "Memory integrity (HVCI) enforced", Severity::Medium)
        .why("HVCI moves kernel code-integrity checks into VTL1, so even a kernel write primitive cannot map unsigned executable pages.")
        .fix("Windows Security → Device security → Core isolation → Memory integrity: On (remove incompatible drivers first).")
        .observed(obs.clone()).expected("HVCI_KMCI_ENABLED").source(src_ci), flag(CI_HVCI_KMCI_ENABLED));
    if flag(CI_HVCI_KMCI_AUDITMODE) == Some(true) {
        out.push(
            Check::new(
                "WCI-005",
                "code integrity",
                "HVCI not in audit mode",
                Severity::Low,
            )
            .why("Audit mode logs violations but does not block them.")
            .fix("Switch HVCI policy to enforced.")
            .observed("audit")
            .expected("enforced")
            .source(src_ci)
            .pass(false),
        );
    }
    push_ci(
        &mut out,
        Check::new(
            "WCI-006",
            "code integrity",
            "HVCI strict mode",
            Severity::Info,
        )
        .why("Strict mode refuses drivers that are not HVCI-compatible.")
        .fix("Enabled automatically on new Windows 11 installs with compatible drivers.")
        .observed(obs.clone())
        .expected("HVCI_KMCI_STRICTMODE")
        .source(src_ci),
        flag(CI_HVCI_KMCI_STRICTMODE),
    );
    push_ci(
        &mut out,
        Check::new(
            "WCI-007",
            "code integrity",
            "User-mode code integrity (WDAC/App Control)",
            Severity::Info,
        )
        .why("A WDAC policy restricts which user-mode binaries may run.")
        .fix("Deploy an App Control for Business policy (even audit) to inventory executables.")
        .observed(obs)
        .expected("UMCI_ENABLED")
        .source(src_ci),
        flag(CI_UMCI_ENABLED),
    );

    let bl = reg_dword(CI_CONFIG, "VulnerableDriverBlocklistEnable");
    out.push(Check::new("WCI-008", "code integrity", "Microsoft vulnerable driver blocklist", Severity::Medium)
        .why("Blocks known-vulnerable signed drivers used in BYOVD attacks to kill EDR or gain ring 0.")
        .fix("Windows Security → Device security → Core isolation → Microsoft Vulnerable Driver Blocklist: On.")
        .observed(bl.map_or("default (unset)".into(), |v| v.to_string()))
        .expected("1")
        .source(format!(r"HKLM\{CI_CONFIG}\VulnerableDriverBlocklistEnable"))
        .pass(bl != Some(0)));

    // --- virtualization-based security ------------------------------------
    let mut ium = [0u8; 16];
    let vbs = query(SYSTEM_ISOLATED_USER_MODE_INFORMATION, &mut ium).then_some(ium[0] & 0x01 != 0);
    let c = Check::new("WVBS-001", "vbs", "Virtualization-based security running (secure kernel)", Severity::Medium)
        .why("VBS hosts the secure kernel (VTL1) that HVCI, Credential Guard and kernel shadow stacks depend on.")
        .fix("Enable VBS via Group Policy (Device Guard → Turn On Virtualization Based Security) with Secure Boot and DMA protection.")
        .expected("SecureKernelRunning")
        .source("ntdll!NtQuerySystemInformation(SystemIsolatedUserModeInformation)");
    out.push(match vbs {
        Some(v) => c
            .observed(if v { "running" } else { "not running" })
            .pass(v),
        None => c.observed("unavailable").na(),
    });
    let lsaiso = process_running("LsaIso.exe");
    let cg_cfg = reg_dword(LSA, "LsaCfgFlags")
        .or_else(|| reg_dword(&format!(r"{DG}\Scenarios\CredentialGuard"), "Enabled"));
    out.push(Check::new("WVBS-002", "vbs", "Credential Guard running (LsaIso)", Severity::Medium)
        .why("Without Credential Guard, NTLM hashes and Kerberos TGTs live in LSASS memory where credential dumpers read them.")
        .fix("Enable Credential Guard (Group Policy or LsaCfgFlags=1) on VBS-capable hardware.")
        .observed(format!("LsaIso {}, policy {}", if lsaiso { "running" } else { "absent" }, cg_cfg.map_or("unset".into(), |v| v.to_string())))
        .expected("LsaIso.exe running")
        .source(format!(r"process list + HKLM\{LSA}\LsaCfgFlags"))
        .pass(lsaiso));
    let kss = reg_dword(&format!(r"{DG}\Scenarios\KernelShadowStacks"), "Enabled");
    out.push(Check::new("WVBS-003", "vbs", "Kernel-mode hardware-enforced stack protection", Severity::Low)
        .why("CET shadow stacks in the kernel stop ROP even after a kernel stack overwrite.")
        .fix("Windows Security → Core isolation → Kernel-mode Hardware-enforced Stack Protection (requires CET-capable CPU, HVCI).")
        .observed(kss.map_or("unset".into(), |v| v.to_string()))
        .expected("1")
        .source(format!(r"HKLM\{DG}\Scenarios\KernelShadowStacks\Enabled"))
        .pass(kss == Some(1)));

    // --- LSA ---------------------------------------------------------------
    let ppl = reg_dword(LSA, "RunAsPPL");
    out.push(Check::new("WLSA-001", "lsa", "LSA protection (RunAsPPL)", Severity::Medium)
        .why("As a Protected Process Light, LSASS cannot be opened for memory reads by non-protected processes, even as admin.")
        .fix(r"Set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1 (or 2 for UEFI-locked) and reboot.")
        .observed(ppl.map_or("unset".into(), |v| v.to_string()))
        .expected("1 | 2")
        .source(format!(r"HKLM\{LSA}\RunAsPPL"))
        .pass(matches!(ppl, Some(1 | 2))));
    let wd = reg_dword(WDIGEST, "UseLogonCredential");
    out.push(Check::new("WLSA-002", "lsa", "WDigest does not cache cleartext passwords", Severity::High)
        .why("UseLogonCredential=1 makes LSASS keep reversible plaintext passwords for every interactive logon.")
        .fix(r"Delete or set HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0.")
        .observed(wd.map_or("unset".into(), |v| v.to_string()))
        .expected("0 | unset")
        .source(format!(r"HKLM\{WDIGEST}\UseLogonCredential"))
        .pass(wd != Some(1)));

    // --- memory / speculative execution -----------------------------------
    // SAFETY: no arguments.
    let dep = unsafe { GetSystemDEPPolicy() };
    out.push(
        Check::new(
            "WMEM-001",
            "memory",
            "System DEP policy",
            if dep == 0 {
                Severity::High
            } else {
                Severity::Low
            },
        )
        .why("DEP marks data pages non-executable; OptIn only protects binaries that request it.")
        .fix("bcdedit /set nx OptOut (or AlwaysOn).")
        .observed(match dep {
            0 => "AlwaysOff",
            1 => "AlwaysOn",
            2 => "OptIn",
            3 => "OptOut",
            _ => "?",
        })
        .expected("OptOut | AlwaysOn")
        .source("kernel32!GetSystemDEPPolicy")
        .pass(dep == 1 || dep == 3),
    );

    let fso = reg_dword(MM, "FeatureSettingsOverride");
    let fsm = reg_dword(MM, "FeatureSettingsOverrideMask");
    let disabled = matches!((fso, fsm), (Some(o), Some(m)) if o & 3 == 3 && m & 3 == 3);
    out.push(Check::new("WSPC-001", "speculation", "Speculative-execution mitigations not disabled by policy", Severity::High)
        .why("FeatureSettingsOverride=3 with mask 3 turns off the Spectre v2 and Meltdown mitigations system-wide.")
        .fix(r"Remove FeatureSettingsOverride / FeatureSettingsOverrideMask under HKLM\...\Memory Management and reboot.")
        .observed(format!("override={:?} mask={:?}", fso, fsm))
        .expected("not 3/3")
        .source(format!(r"HKLM\{MM}"))
        .pass(!disabled));

    let kva = query_u32(SYSTEM_KERNEL_VA_SHADOW_INFORMATION);
    let src_kva = "ntdll!NtQuerySystemInformation(SystemKernelVaShadowInformation)";
    let c = Check::new("WSPC-002", "speculation", "Meltdown (CVE-2017-5754): KVA shadow", Severity::High)
        .why("CPUs vulnerable to rogue data cache load need kernel VA shadowing to keep kernel memory out of user page tables.")
        .fix("Install current Windows updates and CPU microcode; remove policy that disables KVA shadow.")
        .expected("enabled or not required")
        .source(src_kva);
    out.push(match kva {
        Some(k) if k & KVA_REQUIRED_AVAILABLE != 0 => {
            let required = k & KVA_REQUIRED != 0;
            let enabled = k & KVA_ENABLED != 0;
            c.observed(format!("required={required} enabled={enabled}"))
                .pass(!required || enabled)
        }
        Some(k) => c
            .observed(format!("flags {}", hex(k)))
            .pass(k & KVA_ENABLED != 0),
        None => c
            .observed("not reported (pre-2018 build or unsupported)")
            .na(),
    });
    if let Some(k) = kva {
        let required = k & KVA_REQUIRED != 0;
        out.push(
            Check::new(
                "WSPC-003",
                "speculation",
                "L1TF (CVE-2018-3620) mitigation",
                Severity::Medium,
            )
            .why(
                "L1 Terminal Fault lets a guest or process read L1D contents via not-present PTEs.",
            )
            .fix("Install current updates; on Hyper-V hosts enable the core scheduler.")
            .observed(format!(
                "mitigation present={}",
                k & L1TF_MITIGATION_PRESENT != 0
            ))
            .expected("present when the CPU needs KVA shadow")
            .source(src_kva)
            .pass(!required || k & L1TF_MITIGATION_PRESENT != 0),
        );
    }

    let sc = query_u32(SYSTEM_SPECULATION_CONTROL_INFORMATION);
    let src_sc = "ntdll!NtQuerySystemInformation(SystemSpeculationControlInformation)";
    if let Some(s) = sc {
        let bti_ok = s & (SC_BPB_ENABLED | SC_RETPOLINE | SC_ENHANCED_IBRS) != 0;
        let why_off = if s & SC_BPB_DISABLED_POLICY != 0 {
            "disabled by system policy"
        } else if s & SC_BPB_DISABLED_NO_HW != 0 {
            "no hardware support — CPU microcode update missing"
        } else {
            ""
        };
        out.push(
            Check::new(
                "WSPC-004",
                "speculation",
                "Spectre v2 / BTI (CVE-2017-5715) mitigation",
                Severity::High,
            )
            .why("Branch target injection lets user code steer kernel speculative execution.")
            .fix("Apply the OEM BIOS/microcode update and Windows updates; clear disabling policy.")
            .observed(if bti_ok {
                "enabled".to_string()
            } else {
                format!("off — {why_off}")
            })
            .expected("BPB / retpoline / eIBRS")
            .source(src_sc)
            .pass(bti_ok),
        );
        if s & SC_MBCLEAR_REPORTED != 0 {
            let ok = s & (SC_MDS_HW_PROTECTED | SC_MBCLEAR_ENABLED) != 0;
            out.push(Check::new("WSPC-005", "speculation", "MDS (CVE-2018-12130 et al.) mitigation", Severity::Medium)
                .why("Microarchitectural data sampling leaks data across privilege boundaries through CPU buffers.")
                .fix("Install microcode + Windows updates (enables VERW buffer clearing).")
                .observed(if ok { "protected" } else { "not mitigated" })
                .expected("hardware-protected or MbClear enabled")
                .source(src_sc)
                .pass(ok));
        }
        if s & SC_SSBD_REQUIRED != 0 {
            out.push(Check::new("WSPC-006", "speculation", "Speculative Store Bypass (CVE-2018-3639) system-wide", Severity::Info)
                .why("Windows leaves SSBD off by default; enable it where untrusted code shares the host.")
                .fix(r"FeatureSettingsOverride=8, FeatureSettingsOverrideMask=3 (per Microsoft ADV180012).")
                .observed(if s & SC_SSBD_SYSTEM_WIDE != 0 { "on" } else { "off" })
                .expected("on (optional)")
                .source(src_sc)
                .pass(s & SC_SSBD_SYSTEM_WIDE != 0));
        }
        out.push(
            Check::new("WSPC-007", "speculation", "SMEP present", Severity::Low)
                .why("Supervisor Mode Execution Prevention stops the kernel executing user pages.")
                .fix("Hardware feature; enable in firmware if hidden or upgrade the CPU.")
                .observed(if s & SC_SMEP_PRESENT != 0 {
                    "yes"
                } else {
                    "no"
                })
                .expected("yes")
                .source(src_sc)
                .pass(s & SC_SMEP_PRESENT != 0),
        );
    }

    (
        out,
        WinReport {
            build,
            ci_options: ci,
            vbs_running: vbs,
            kva_flags: kva,
            spec_flags: sc,
        },
    )
}
