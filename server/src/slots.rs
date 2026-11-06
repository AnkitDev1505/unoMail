//! Connection slots shared fairly between networks.
//!
//! A listener has a fixed number of slots. Below that number every connection is admitted as
//! long as its network (an IPv4 address, an IPv6 /64) is under its own limit. At the limit the
//! newcomer is not simply refused, which would let a handful of networks that open connections
//! and never use them shut everybody else out: the oldest connection of the group holding the
//! most slots gives way instead, provided that group holds clearly more than the newcomer's.
//! Groups are IPv4 addresses and IPv6 /48s, so that one holder of a large IPv6 prefix counts
//! once however many /64s it spreads over.

use std::{collections::{BTreeMap, HashMap}, future::Future, net::IpAddr, sync::Arc};

use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

pub struct Slots {
    state: Mutex<State>,
    max_total: usize,
    max_per_network: usize,
}

#[derive(Default)]
struct State {
    next: u64,
    total: usize,
    /// Open connections per network (the per-network limit).
    networks: HashMap<String, usize>,
    /// Open connections per fairness group, oldest first: id -> (network, cancellation).
    groups: HashMap<String, BTreeMap<u64, (String, CancellationToken)>>,
}

impl State {
    /// Forgets a connection; returns its cancellation if it was still counted.
    fn remove(&mut self, group: &str, id: u64) -> Option<CancellationToken> {
        let members = self.groups.get_mut(group)?;
        let (network, cancel) = members.remove(&id)?;
        if members.is_empty() {
            self.groups.remove(group);
        }
        if let Some(count) = self.networks.get_mut(&network) {
            *count -= 1;
            if *count == 0 {
                self.networks.remove(&network);
            }
        }
        self.total -= 1;
        Some(cancel)
    }
}

/// The group a client is counted in when slots are shared out: the address itself for IPv4,
/// the /48 for IPv6.
pub fn fairness_group(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) if v6.to_ipv4_mapped().is_none() => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
        _ => crate::auth::network(ip),
    }
}

impl Slots {
    pub fn new(max_total: usize, max_per_network: usize) -> Arc<Self> {
        Arc::new(Self { state: Mutex::new(State::default()), max_total, max_per_network })
    }

    /// A slot for a connection from `ip`, or `None` when it has to be refused. `exempt`
    /// addresses (trusted proxies, loopback) carry many clients and skip the per-network limit.
    pub fn take(self: &Arc<Self>, ip: IpAddr, exempt: bool) -> Option<Slot> {
        let network = crate::auth::network(ip);
        let group = fairness_group(ip);
        let mut state = self.state.lock();
        if !exempt && state.networks.get(&network).copied().unwrap_or(0) >= self.max_per_network {
            return None;
        }
        if state.total >= self.max_total {
            let own = state.groups.get(&group).map_or(0, BTreeMap::len);
            // The largest group; among equally large ones, the one with the oldest connection.
            let (largest, size, oldest) = state
                .groups
                .iter()
                .filter_map(|(name, members)| Some((name, members.len(), *members.keys().next()?)))
                .max_by_key(|(_, size, oldest)| (*size, std::cmp::Reverse(*oldest)))?;
            // Equal shares stay: otherwise groups of the same size would just take turns.
            if size <= own + 1 {
                return None;
            }
            let largest = largest.clone();
            if let Some(cancel) = state.remove(&largest, oldest) {
                cancel.cancel();
            }
        }
        let id = state.next;
        state.next += 1;
        let cancel = CancellationToken::new();
        state.groups.entry(group.clone()).or_default().insert(id, (network.clone(), cancel.clone()));
        *state.networks.entry(network).or_default() += 1;
        state.total += 1;
        Some(Slot { slots: self.clone(), id, group, cancel })
    }

    /// Connections currently holding a slot.
    pub fn open(&self) -> usize {
        self.state.lock().total
    }
}

/// One admitted connection. Dropping it frees the slot.
pub struct Slot {
    slots: Arc<Slots>,
    id: u64,
    group: String,
    cancel: CancellationToken,
}

impl Slot {
    /// Whether the slot was given to a newcomer; the connection should end.
    pub fn is_evicted(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// Runs `work` until it finishes or the slot is given away, whichever comes first.
    pub async fn guard<F: Future>(&self, work: F) -> Option<F::Output> {
        tokio::select! {
            out = work => Some(out),
            () = self.cancel.cancelled() => None,
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.slots.state.lock().remove(&self.group, self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn a_few_networks_cannot_hold_every_slot() {
        let slots = Slots::new(8, 4);
        // Two attackers fill the listener with idle connections.
        let held: Vec<Slot> = (0..8).map(|i| slots.take(ip(if i % 2 == 0 { "192.0.2.1" } else { "192.0.2.2" }), false).unwrap()).collect();
        assert_eq!(slots.open(), 8);
        // A new client still gets in: the oldest connection of a largest group makes room.
        let visitor = slots.take(ip("198.51.100.7"), false).expect("a newcomer must not be locked out");
        assert!(held[0].is_evicted(), "the oldest connection of the largest group gives way");
        assert_eq!(held.iter().filter(|s| s.is_evicted()).count(), 1);
        assert_eq!(slots.open(), 8);
        // Reconnecting does not let an attacker push others out once the shares are even.
        assert!(slots.take(ip("192.0.2.1"), false).is_none());
        assert!(slots.take(ip("192.0.2.2"), false).is_none());
        assert!(!visitor.is_evicted());
    }

    #[test]
    fn evicted_slots_are_not_counted_twice() {
        let slots = Slots::new(2, 2);
        let a = slots.take(ip("192.0.2.1"), false).unwrap();
        let b = slots.take(ip("192.0.2.1"), false).unwrap();
        let c = slots.take(ip("192.0.2.9"), false).unwrap();
        assert!(a.is_evicted() && !b.is_evicted());
        drop(a);
        assert_eq!(slots.open(), 2);
        drop((b, c));
        assert_eq!(slots.open(), 0);
    }

    #[test]
    fn networks_have_their_own_limit_except_shared_ones() {
        let slots = Slots::new(100, 2);
        let _held: Vec<Slot> = (0..2).map(|_| slots.take(ip("192.0.2.1"), false).unwrap()).collect();
        assert!(slots.take(ip("192.0.2.1"), false).is_none());
        assert!(slots.take(ip("192.0.2.1"), true).is_some(), "a trusted proxy carries many clients");
        assert!(slots.take(ip("192.0.2.2"), false).is_some());
    }

    #[test]
    fn an_ipv6_prefix_counts_once_however_it_is_split() {
        assert_eq!(fairness_group(ip("2001:db8:1:2::1")), fairness_group(ip("2001:db8:1:ff00::1")));
        assert_ne!(fairness_group(ip("2001:db8:1::1")), fairness_group(ip("2001:db8:2::1")));
        assert_eq!(fairness_group(ip("192.0.2.1")), "192.0.2.1");
        let slots = Slots::new(4, 1);
        // Four /64s of one /48 fill the listener; a visitor from elsewhere still gets in.
        let held: Vec<Slot> = (0..4).map(|i| slots.take(ip(&format!("2001:db8:1:{i:x}::1")), false).unwrap()).collect();
        assert!(slots.take(ip("2001:db8:1:99::1"), false).is_none(), "the prefix already holds the most");
        assert!(slots.take(ip("203.0.113.5"), false).is_some());
        assert_eq!(held.iter().filter(|s| s.is_evicted()).count(), 1);
    }

    #[tokio::test]
    async fn an_evicted_connection_stops() {
        let slots = Slots::new(2, 2);
        let first = slots.take(ip("192.0.2.1"), false).unwrap();
        let _other = slots.take(ip("192.0.2.1"), false).unwrap();
        let work = first.guard(std::future::pending::<()>());
        let _second = slots.take(ip("198.51.100.1"), false).unwrap();
        assert_eq!(work.await, None);
    }
}
