//! STAN (DE 11) allocation shared by everything in one process that talks to the acquirers.
//!
//! Every running card-service is told its slot (`instance` of `instances`, unique across all regions) and only
//! ever hands out STANs `k * instances + instance + 1`. No two processes can mint the same STAN, and within a
//! process the fleet's transactions and every pool's echoes draw from one counter, so they can't collide either.

use std::sync::atomic::{AtomicU32, Ordering};

const STAN_MAX: u32 = 999_999;

#[derive(Debug)]
pub struct StanSource {
    counter: AtomicU32,
    instance: u32,
    instances: u32,
}

impl StanSource {
    /// Slot `instance` of `instances`. At most 999 instances, so each still gets at least 1,001 STANs per cycle.
    pub fn new(instance: u32, instances: u32) -> Result<Self, String> {
        if !(1..=999).contains(&instances) || instance >= instances {
            return Err(format!("STAN slot {instance} of {instances}: need 0 <= instance < instances <= 999"));
        }
        Ok(Self { counter: AtomicU32::new(0), instance, instances })
    }

    /// The only instance: all of 000001..=999999.
    pub fn single() -> Self {
        Self::new(0, 1).expect("valid")
    }

    /// The next six-digit STAN in this instance's slot, wrapping within it.
    pub fn next(&self) -> String {
        let per_instance = STAN_MAX / self.instances;
        let k = self.counter.fetch_add(1, Ordering::Relaxed) % per_instance;
        format!("{:06}", k * self.instances + self.instance + 1)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn instances_never_share_a_stan_and_each_cycles_within_its_slot() {
        let instances = 3;
        let sources: Vec<_> = (0..instances).map(|i| StanSource::new(i, instances).unwrap()).collect();
        let per = (STAN_MAX / instances) as usize;
        let mut seen = HashSet::new();
        for source in &sources {
            for _ in 0..per {
                let stan = source.next();
                assert_eq!(stan.len(), 6);
                let n: u32 = stan.parse().unwrap();
                assert!((1..=STAN_MAX).contains(&n), "{stan}");
                assert!(seen.insert(stan.clone()), "{stan} minted twice");
            }
        }
        assert_eq!(seen.len(), per * instances as usize);
        assert_eq!(sources[1].next(), "000002", "after a full cycle, slot 1 starts over");
    }

    #[test]
    fn a_single_instance_uses_the_whole_range() {
        let source = StanSource::single();
        assert_eq!((source.next(), source.next()), ("000001".into(), "000002".into()));
    }

    #[test]
    fn impossible_slots_are_rejected() {
        assert!(StanSource::new(3, 3).is_err());
        assert!(StanSource::new(0, 0).is_err());
        assert!(StanSource::new(0, 1_000).is_err());
    }
}
