//! Check results, the hardening score, and conversion into findings.

use serde::Serialize;

use crate::report::{Finding, Severity};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Fail,
    /// Knob absent on this kernel/build, or not readable without privilege.
    Na,
}

#[derive(Clone, Debug, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub area: &'static str,
    pub name: String,
    pub status: Status,
    pub severity: Severity,
    pub observed: String,
    pub expected: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub why: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub fix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl Check {
    pub fn new(
        id: &'static str,
        area: &'static str,
        name: impl Into<String>,
        severity: Severity,
    ) -> Self {
        Self {
            id,
            area,
            name: name.into(),
            status: Status::Na,
            severity,
            observed: String::new(),
            expected: String::new(),
            why: String::new(),
            fix: String::new(),
            source: None,
        }
    }

    pub fn pass(mut self, ok: bool) -> Self {
        self.status = if ok { Status::Pass } else { Status::Fail };
        self
    }

    pub fn na(mut self) -> Self {
        self.status = Status::Na;
        self
    }

    pub fn observed(mut self, v: impl Into<String>) -> Self {
        self.observed = v.into();
        self
    }

    pub fn expected(mut self, v: impl Into<String>) -> Self {
        self.expected = v.into();
        self
    }

    pub fn why(mut self, v: impl Into<String>) -> Self {
        self.why = v.into();
        self
    }

    pub fn fix(mut self, v: impl Into<String>) -> Self {
        self.fix = v.into();
        self
    }

    pub fn source(mut self, v: impl Into<String>) -> Self {
        self.source = Some(v.into());
        self
    }
}

fn weight(s: Severity) -> u32 {
    match s {
        Severity::Critical => 10,
        Severity::High => 6,
        Severity::Medium => 3,
        Severity::Low => 1,
        Severity::Info => 0,
    }
}

#[derive(Debug, Serialize)]
pub struct Score {
    pub score: u32,
    pub passed: usize,
    pub failed: usize,
    pub not_applicable: usize,
    pub grade: &'static str,
}

/// Severity-weighted share of applicable checks that pass, 0–100.
pub fn score(checks: &[Check]) -> Score {
    let (mut got, mut total) = (0u32, 0u32);
    for c in checks.iter().filter(|c| c.status != Status::Na) {
        let w = weight(c.severity).max(1);
        total += w;
        if c.status == Status::Pass {
            got += w;
        }
    }
    let score = (got * 100 + total / 2).checked_div(total).unwrap_or(0);
    Score {
        score,
        passed: checks.iter().filter(|c| c.status == Status::Pass).count(),
        failed: checks.iter().filter(|c| c.status == Status::Fail).count(),
        not_applicable: checks.iter().filter(|c| c.status == Status::Na).count(),
        grade: match score {
            90.. => "A",
            80..=89 => "B",
            65..=79 => "C",
            50..=64 => "D",
            _ => "F",
        },
    }
}

pub fn findings(checks: &[Check]) -> Vec<Finding> {
    checks
        .iter()
        .filter(|c| c.status == Status::Fail)
        .map(|c| {
            let mut f = Finding::new(c.id, c.severity, c.name.clone())
                .detail(c.why.clone())
                .fix(c.fix.clone());
            if !c.observed.is_empty() || !c.expected.is_empty() {
                f = f.evidence(format!(
                    "observed: {}   expected: {}",
                    c.observed, c.expected
                ));
            }
            if let Some(s) = &c.source {
                f = f.source(s.clone());
            }
            f
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_is_weighted_and_ignores_na() {
        let c = vec![
            Check::new("A", "x", "a", Severity::High).pass(true),
            Check::new("B", "x", "b", Severity::Low).pass(false),
            Check::new("C", "x", "c", Severity::Critical).na(),
        ];
        let s = score(&c);
        assert_eq!(s.score, 86); // 6 / 7
        assert_eq!((s.passed, s.failed, s.not_applicable), (1, 1, 1));
        assert_eq!(findings(&c).len(), 1);
    }
}
