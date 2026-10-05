//! Pool indices: how samples and per-ring packet counts name a configured
//! interface.
//!
//! An interface keeps its index for as long as it stays configured, so its
//! counters in every ring stay its own across configuration changes. A
//! freed index is handed out again only once all of them have been used in
//! this epoch; a reader seeing a different name at an index (the status
//! says which) must treat that index's counters as restarted.

use packetframe_sampler_shm::layout::MAX_INTERFACES;

#[derive(Debug, Clone, Default)]
pub struct PoolIndexes {
    /// The name holding each index now.
    holder: Vec<Option<String>>,
    /// Indices ever handed out this epoch: one past the highest.
    used: usize,
}

impl PoolIndexes {
    pub fn new() -> Self {
        Self {
            holder: vec![None; MAX_INTERFACES],
            used: 0,
        }
    }

    /// The pool index of each of `names` (unique, at most
    /// [`MAX_INTERFACES`], as a valid configuration guarantees), keeping
    /// every index a name already had.
    pub fn assign(&mut self, names: &[String]) -> Vec<u8> {
        assert!(names.len() <= MAX_INTERFACES);
        for h in &mut self.holder {
            if h.as_ref().is_some_and(|n| !names.contains(n)) {
                *h = None;
            }
        }
        names
            .iter()
            .map(|name| {
                if let Some(i) = self.holder.iter().position(|h| h.as_ref() == Some(name)) {
                    return i as u8;
                }
                let i = if self.used < MAX_INTERFACES {
                    self.used += 1;
                    self.used - 1
                } else {
                    self.holder
                        .iter()
                        .position(Option::is_none)
                        .expect("at most 64 names, so a free index exists")
                };
                self.holder[i] = Some(name.clone());
                i as u8
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn an_interface_keeps_its_index_while_configured() {
        let mut p = PoolIndexes::new();
        assert_eq!(p.assign(&names(&["a", "b", "c"])), [0, 1, 2]);
        assert_eq!(
            p.assign(&names(&["c", "a"])),
            [2, 0],
            "order does not matter"
        );
        assert_eq!(
            p.assign(&names(&["d", "a"])),
            [3, 0],
            "b's 1 is not reused yet"
        );
        assert_eq!(p.assign(&names(&["b"])), [4], "b back: a new index");
    }

    #[test]
    fn indices_are_reused_only_after_all_were_used() {
        let mut p = PoolIndexes::new();
        let all: Vec<String> = (0..MAX_INTERFACES).map(|i| format!("p{i}")).collect();
        let idx = p.assign(&all);
        assert_eq!(idx, (0..MAX_INTERFACES as u8).collect::<Vec<_>>());
        let mut fewer = all.clone();
        fewer.remove(5);
        fewer.remove(9); // p10
        p.assign(&fewer);
        let mut more = fewer.clone();
        more.push("new".into());
        let got = p.assign(&more);
        assert_eq!(*got.last().unwrap(), 5, "lowest freed index");
        assert!(got.iter().all(|&i| usize::from(i) < MAX_INTERFACES));
    }
}
