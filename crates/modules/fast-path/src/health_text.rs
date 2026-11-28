//! Small formatting helpers for the `module health` row messages, so
//! every fast-path row renders ages, lists and quoted reasons the same
//! way. Portable: the rows are tested on every host.

/// An age in one unit, rounded down: `45s`, `12m`, `37h`, `4d`. The same
/// rule the status renderer uses for a row's `last_success_age_seconds`,
/// so an age inside a message reads like the one beside it.
pub fn age(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m", secs / 60),
        3600..=172_799 => format!("{}h", secs / 3600),
        _ => format!("{}d", secs / 86_400),
    }
}

/// How many items a row lists before it says `+N more`.
pub const LIST_CAP: usize = 5;

/// `a, b, c`, capped at [`LIST_CAP`] items with `+N more` after them.
pub fn list(items: &[String]) -> String {
    let mut out = items
        .iter()
        .take(LIST_CAP)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if items.len() > LIST_CAP {
        out.push_str(&format!(" +{} more", items.len() - LIST_CAP));
    }
    out
}

/// The leading clause of a reason written for the journal: everything
/// before its first `; ` or ` — `. Those reasons state the fact first and
/// explain it after; a row carries only the fact.
pub fn brief(why: &str) -> &str {
    let cut = [why.find("; "), why.find(" — ")]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(why.len());
    why[..cut].trim_end()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ages_use_one_unit_rounded_down() {
        assert_eq!(age(0), "0s");
        assert_eq!(age(59), "59s");
        assert_eq!(age(60), "1m");
        assert_eq!(age(3599), "59m");
        assert_eq!(age(3600), "1h");
        assert_eq!(age(47 * 3600 + 3599), "47h");
        assert_eq!(age(48 * 3600), "2d");
        assert_eq!(age(97 * 3600), "4d");
    }

    #[test]
    fn lists_are_capped() {
        let items: Vec<String> = (0..7).map(|i| format!("eth{i}")).collect();
        assert_eq!(list(&items[..2]), "eth0, eth1");
        assert_eq!(list(&items), "eth0, eth1, eth2, eth3, eth4 +2 more");
    }

    #[test]
    fn brief_keeps_the_leading_clause() {
        assert_eq!(brief("a fact; why it matters"), "a fact");
        assert_eq!(brief("a fact — why; more"), "a fact");
        assert_eq!(brief("only a fact"), "only a fact");
    }
}
