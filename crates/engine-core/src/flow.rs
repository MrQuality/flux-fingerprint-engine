use std::net::IpAddr;
use crate::{FlowState, FlowOutcome};

/// Canonical 5-tuple for flow identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

/// Core state and reassembly metadata for a single TCP flow.
#[derive(Debug, Clone)]
pub struct FlowEntry {
    pub key: FlowKey,
    pub state: FlowState,
    pub last_timestamp_ns: u64,
    pub start_seq: u32,
    pub next_expected_seq: u32,
    pub fragment_count: u8,
    // Note: Scratchpad mappings will be added in the next sub-task.
}

/// A fixed-size, shared-nothing connection table using quadratic probing.
pub struct FlowMap {
    entries: Vec<Option<FlowEntry>>,
    capacity: usize,
    probe_limit: usize,
    count: usize,
}

impl FlowMap {
    /// Creates a new FlowMap with a power-of-two capacity.
    pub fn new(capacity: usize) -> Self {
        let actual_capacity = capacity.next_power_of_two();
        Self {
            entries: vec![None; actual_capacity],
            capacity: actual_capacity,
            probe_limit: 16, // ADR-002 limit
            count: 0,
        }
    }

    /// Primary lookup/insertion method using quadratic probing.
    ///
    /// Returns a mutable reference to an existing entry, or a slot for a new one.
    /// Emits CollisionDropped if the probe limit is exceeded.
    pub fn acquire(&mut self, key: &FlowKey) -> Result<&mut FlowEntry, FlowOutcome> {
        let hash = self.calculate_hash(key);
        let mask = self.capacity - 1;
        let mut first_free = None;

        for i in 0..self.probe_limit {
            let idx = (hash + i * i) & mask;

            match &self.entries[idx] {
                Some(entry) => {
                    if entry.key == *key {
                        return Ok(self.entries[idx].as_mut().unwrap());
                    }
                }
                None => {
                    if first_free.is_none() {
                        first_free = Some(idx);
                    }
                    // In a simple hash table without deletion (or using tombstones), 
                    // we could break here. For our current implementation, an empty 
                    // slot means the key definitely doesn't exist further in the probe chain.
                    break;
                }
            }
        }

        if let Some(idx) = first_free {
            self.count += 1;
            self.entries[idx] = Some(FlowEntry {
                key: *key,
                state: FlowState::SynSeen,
                last_timestamp_ns: 0,
                start_seq: 0,
                next_expected_seq: 0,
                fragment_count: 0,
            });
            return Ok(self.entries[idx].as_mut().unwrap());
        }

        Err(FlowOutcome::CollisionDropped)
    }

    fn calculate_hash(&self, key: &FlowKey) -> usize {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut s = DefaultHasher::new();
        key.hash(&mut s);
        s.finish() as usize
    }

    pub fn load_factor(&self) -> f64 {
        self.count as f64 / self.capacity as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn mock_key(port: u16) -> FlowKey {
        FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: port,
            dst_port: 443,
            protocol: 6,
        }
    }

    #[test]
    fn test_flow_map_insertion() {
        let mut map = FlowMap::new(1024);
        let key = mock_key(1234);
        let entry = map.acquire(&key).unwrap();
        assert_eq!(entry.key.src_port, 1234);
        assert_eq!(map.count, 1);
    }

    #[test]
    fn test_flow_map_saturation_signal() {
        let mut map = FlowMap::new(2); // Capacity becomes 2
        map.probe_limit = 1; // Extremely restrictive
        
        // Fill the only slots
        map.acquire(&mock_key(1)).unwrap();
        map.acquire(&mock_key(2)).unwrap();
        
        // Any other key must fail immediately due to probe limit
        let result = map.acquire(&mock_key(3));
        assert_eq!(result.err(), Some(FlowOutcome::CollisionDropped));
    }
}
