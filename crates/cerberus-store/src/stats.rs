//! Stats aggregation for audit events by provider, tool, and flag.

use std::collections::HashMap;

use serde::Serialize;

use crate::event::AuditEvent;

/// Statistics aggregated by provider.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProviderStats {
    /// Provider name.
    pub provider: String,
    /// Total number of events.
    pub total: usize,
    /// Count per action.
    pub by_action: HashMap<String, usize>,
    /// Top flags.
    pub top_flags: Vec<(String, usize)>,
}

/// Statistics aggregated by tool.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ToolStats {
    /// Tool name.
    pub tool: String,
    /// Total number of events.
    pub total: usize,
    /// Count per action.
    pub by_action: HashMap<String, usize>,
}

/// Statistics summary.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatsSummary {
    /// Total number of events.
    pub total: usize,
    /// Per provider.
    pub by_provider: Vec<ProviderStats>,
    /// Per tool.
    pub by_tool: Vec<ToolStats>,
    /// Global top flags.
    pub top_flags: Vec<(String, usize)>,
    /// Count per action.
    pub by_action: HashMap<String, usize>,
}

/// Group events by provider and compute statistics.
#[must_use]
pub fn by_provider(events: &[AuditEvent]) -> Vec<ProviderStats> {
    let mut grouped: HashMap<String, Vec<&AuditEvent>> = HashMap::new();
    for event in events {
        grouped.entry(event.provider.clone()).or_default().push(event);
    }

    let mut stats: Vec<ProviderStats> = grouped
        .into_iter()
        .map(|(provider, evts)| {
            let total = evts.len();
            let mut by_action: HashMap<String, usize> = HashMap::new();
            let mut flag_counts: HashMap<String, usize> = HashMap::new();

            for event in &evts {
                *by_action.entry(event.action_taken.clone()).or_insert(0) += 1;
                for (flag, count) in &event.counts {
                    *flag_counts.entry(flag.clone()).or_insert(0) += count;
                }
            }

            let mut top_flags: Vec<(String, usize)> = flag_counts.into_iter().collect();
            top_flags.sort_unstable_by_key(|(_, count)| std::cmp::Reverse(*count));
            top_flags.truncate(10);

            ProviderStats {
                provider,
                total,
                by_action,
                top_flags,
            }
        })
        .collect();

    stats.sort_unstable_by_key(|s| std::cmp::Reverse(s.total));
    stats
}

/// Group events by tool.
#[must_use]
pub fn by_tool(events: &[AuditEvent]) -> Vec<ToolStats> {
    let mut grouped: HashMap<String, Vec<&AuditEvent>> = HashMap::new();
    for event in events {
        grouped.entry(event.tool.clone()).or_default().push(event);
    }

    let mut stats: Vec<ToolStats> = grouped
        .into_iter()
        .map(|(tool, evts)| {
            let total = evts.len();
            let mut by_action: HashMap<String, usize> = HashMap::new();

            for event in &evts {
                *by_action.entry(event.action_taken.clone()).or_insert(0) += 1;
            }

            ToolStats { tool, total, by_action }
        })
        .collect();

    stats.sort_unstable_by_key(|s| std::cmp::Reverse(s.total));
    stats
}

/// Compute a complete statistics summary.
#[must_use]
pub fn summary(events: &[AuditEvent]) -> StatsSummary {
    let total = events.len();
    let by_provider = by_provider(events);
    let by_tool = by_tool(events);

    let mut flag_counts: HashMap<String, usize> = HashMap::new();
    let mut by_action: HashMap<String, usize> = HashMap::new();
    for event in events {
        *by_action.entry(event.action_taken.clone()).or_insert(0) += 1;
        for (flag, count) in &event.counts {
            *flag_counts.entry(flag.clone()).or_insert(0) += count;
        }
    }

    let mut top_flags: Vec<(String, usize)> = flag_counts.into_iter().collect();
    top_flags.sort_unstable_by_key(|(_, count)| std::cmp::Reverse(*count));
    top_flags.truncate(10);

    StatsSummary {
        total,
        by_provider,
        by_tool,
        top_flags,
        by_action,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::AuditEvent;
    use cerberus_engine::engine::Finding;
    use cerberus_engine::rule::{Action, Category, Severity};

    fn make_finding(flag: &str, action: Action) -> Finding {
        Finding {
            flag: flag.to_string(),
            category: Category::Secrets,
            severity: Severity::High,
            action,
            start: 0,
            end: 5,
            hashed_value: "sha256:test".to_string(),
        }
    }

    fn make_event(provider: &str, tool: &str, flag: &str, action: Action) -> AuditEvent {
        AuditEvent::from_findings(&[make_finding(flag, action)], action, "local", tool, provider)
    }

    #[test]
    fn stats_by_provider_groups_correctly() {
        let events = vec![
            make_event("anthropic", "claude-code", "sk-ant", Action::Block),
            make_event("openai", "opencode", "sk-abc", Action::Redact),
            make_event("anthropic", "claude-code", "sk-ant", Action::Warn),
        ];
        let stats = by_provider(&events);
        assert_eq!(stats.len(), 2);
        let anthropic = stats.iter().find(|s| s.provider == "anthropic").unwrap();
        assert_eq!(anthropic.total, 2);
        let openai = stats.iter().find(|s| s.provider == "openai").unwrap();
        assert_eq!(openai.total, 1);
    }

    #[test]
    fn stats_by_tool_groups_correctly() {
        let events = vec![
            make_event("anthropic", "claude-code", "f1", Action::Block),
            make_event("openai", "opencode", "f2", Action::Redact),
            make_event("openai", "opencode", "f3", Action::Warn),
        ];
        let stats = by_tool(&events);
        assert_eq!(stats.len(), 2);
        let codex = stats.iter().find(|s| s.tool == "opencode").unwrap();
        assert_eq!(codex.total, 2);
    }

    #[test]
    fn stats_summary_computes_all_metrics() {
        let events = vec![
            make_event("a", "t1", "flag.x", Action::Block),
            make_event("a", "t1", "flag.x", Action::Redact),
            make_event("b", "t2", "flag.y", Action::Block),
        ];
        let s = summary(&events);
        assert_eq!(s.total, 3);
        assert_eq!(s.by_provider.len(), 2);
        assert_eq!(s.by_tool.len(), 2);
        assert!(!s.top_flags.is_empty());
        assert_eq!(*s.by_action.get("block").unwrap(), 2);
        assert_eq!(*s.by_action.get("redact").unwrap(), 1);
    }

    #[test]
    fn stats_top_flags_ordered_by_count() {
        let events = vec![
            make_event("a", "t", "frequent", Action::Block),
            make_event("a", "t", "frequent", Action::Block),
            make_event("a", "t", "rare", Action::Warn),
        ];
        let s = summary(&events);
        assert_eq!(s.top_flags[0].0, "frequent");
        assert!(s.top_flags[0].1 >= s.top_flags[1].1);
    }

    #[test]
    fn stats_empty_events_return_empty_summary() {
        let s = summary(&[]);
        assert_eq!(s.total, 0);
        assert!(s.by_provider.is_empty());
        assert!(s.by_tool.is_empty());
        assert!(s.top_flags.is_empty());
        assert!(s.by_action.is_empty());
    }
}
