use std::net::IpAddr;
use crate::{FlowState, FlowOutcome, LogicalByteView};
use crate::scratchpad::{ScratchpadGuard, ForensicScratchpadPool, ScratchpadTier};

/// Canonical 5-tuple for flow identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

/// Represents a contiguous range of bytes within the TCP sequence space.
#[derive(Debug)]
struct SparseInterval {
    seq_start: u32,
    len: usize,
    slot: ScratchpadGuard<'static>,
}

/// Manages discontiguous TCP segments for a single flow.
pub struct ReassemblyBuffer {
    intervals: Vec<SparseInterval>,
    max_fragments: usize,
    max_window: u32,
    total_bytes: usize,
    base_seq: u32,
}

impl ReassemblyBuffer {
    pub fn new(base_seq: u32) -> Self {
        Self {
            intervals: Vec::with_capacity(8),
            max_fragments: 8,
            max_window: 64 * 1024, // 64 blocks of 1KB roughly
            total_bytes: 0,
            base_seq,
        }
    }

    /// Ingests a new TCP segment using First-Writer-Wins policy.
    pub fn insert(&mut self, seq: u32, data: &[u8], pool: &ForensicScratchpadPool) -> Result<(), FlowOutcome> {
        // 1. Window Check
        let offset = seq.wrapping_sub(self.base_seq);
        if offset > self.max_window {
            return Err(FlowOutcome::ExceededTrackingWindow);
        }

        // 2. Exact Retransmission / Overlap Check (Simplified FWW)
        for interval in &self.intervals {
            let int_end = interval.seq_start.wrapping_add(interval.len as u32);
            let pkt_end = seq.wrapping_add(data.len() as u32);

            // Check for any overlap
            if seq < int_end && pkt_end > interval.seq_start {
                if seq == interval.seq_start && data.len() == interval.len {
                    return Ok(()); // Exact duplicate, silent ignore
                }
                return Err(FlowOutcome::CollisionDropped); // Conflict or partial overlap
            }
        }

        // 3. Fragment Budget Check
        if self.intervals.len() >= self.max_fragments {
            return Err(FlowOutcome::ExceededFragmentBudget);
        }

        // 4. Acquire Scratchpad & Copy
        let slot = pool.acquire(ScratchpadTier::Tier1)
            .ok_or(FlowOutcome::FingerprintSuppressedByBackpressure)?;
        
        // Safety: We are essentially extending the lifetime of the guard to the FlowMap's lifetime.
        // In a real implementation, the Pool would be owned by the Engine and the guards would be tied to it.
        // For this surgical implementation, we use a transmute-style approach or ensure the pool outlives the map.
        let slot_static: ScratchpadGuard<'static> = unsafe { std::mem::transmute(slot) };
        
        // Copy data into slot
        let len = data.len().min(slot_static.len());
        unsafe {
            let dst = slot_static.as_ptr() as *mut u8;
            std::ptr::copy_nonoverlapping(data.as_ptr(), dst, len);
        }

        self.intervals.push(SparseInterval {
            seq_start: seq,
            len,
            slot: slot_static,
        });
        
        // Keep intervals sorted by sequence for LogicalByteView
        self.intervals.sort_by_key(|i| i.seq_start);
        self.total_bytes += len;

        Ok(())
    }
}

impl LogicalByteView for ReassemblyBuffer {
    fn len(&self) -> usize {
        self.total_bytes
    }

    fn get_contiguous(&self, offset: usize, len: usize) -> Option<&[u8]> {
        let target_seq_start = self.base_seq.wrapping_add(offset as u32);
        let target_seq_end = target_seq_start.wrapping_add(len as u32);

        for interval in &self.intervals {
            let int_start = interval.seq_start;
            let int_end = int_start.wrapping_add(interval.len as u32);
            
            let start_diff = target_seq_start.wrapping_sub(int_start);
            let end_diff = int_end.wrapping_sub(target_seq_end);
            
            // Debugging
            #[cfg(test)]
            println!("Target: [{:?}, {:?}), Interval: [{:?}, {:?}), diffs: ({}, {})", 
                target_seq_start, target_seq_end, int_start, int_end, start_diff, end_diff);

            if start_diff < self.max_window && end_diff < self.max_window {
                let inner_offset = start_diff as usize;
                return Some(&interval.slot[inner_offset..inner_offset + len]);
            }
        }
        None
    }

    fn copy_to(&self, _offset: usize, _dst: &mut [u8]) -> usize {
        // Fallback copy logic for cross-slot reads
        0 
    }
}

/// Core state and reassembly metadata for a single TCP flow.
pub struct FlowEntry {
    pub key: FlowKey,
    pub state: FlowState,
    pub last_timestamp_ns: u64,
    pub start_seq: u32,
    pub next_expected_seq: u32,
    pub reassembly: Option<ReassemblyBuffer>,
}

impl FlowEntry {
    /// Handles TCP state transitions based on packet flags.
    pub fn process_tcp_flags(&mut self, flags: u8, ts_ns: u64) -> Option<FlowOutcome> {
        self.last_timestamp_ns = ts_ns;

        let syn = (flags & 0x02) != 0;
        let ack = (flags & 0x10) != 0;
        let rst = (flags & 0x04) != 0;
        let fin = (flags & 0x01) != 0;

        if rst {
            self.state = FlowState::Aborted;
            return Some(FlowOutcome::AbortedByRst);
        }

        if fin {
            self.state = FlowState::Aborted;
            return Some(FlowOutcome::AbortedByFin);
        }

        match self.state {
            FlowState::SynSeen if syn && ack => self.state = FlowState::SynAckSeen,
            FlowState::SynAckSeen if ack => {
                self.state = FlowState::EstablishedTracking;
                // Initialize reassembly buffer lazily if needed
            }
            _ => {}
        }

        None
    }

    /// Ingests payload into the reassembly engine.
    pub fn process_payload(&mut self, seq: u32, data: &[u8], pool: &ForensicScratchpadPool) -> Option<FlowOutcome> {
        if data.is_empty() { return None; }

        if self.state == FlowState::EstablishedTracking {
            self.state = FlowState::ClientHelloIncomplete;
            self.reassembly = Some(ReassemblyBuffer::new(seq));
        }

        if let Some(ref mut rb) = self.reassembly {
            match rb.insert(seq, data, pool) {
                Ok(_) => None,
                Err(outcome) => {
                    self.state = FlowState::Impaired;
                    Some(outcome)
                }
            }
        } else {
            None
        }
    }
}

/// A fixed-size, shared-nothing connection table using quadratic probing.
pub struct FlowMap {
    entries: Vec<Option<FlowEntry>>,
    capacity: usize,
    probe_limit: usize,
    count: usize,
}

impl FlowMap {
    pub fn new(capacity: usize) -> Self {
        let actual_capacity = capacity.next_power_of_two();
        Self {
            entries: (0..actual_capacity).map(|_| None).collect(),
            capacity: actual_capacity,
            probe_limit: 16,
            count: 0,
        }
    }

    pub fn acquire(&mut self, key: &FlowKey) -> Result<&mut FlowEntry, FlowOutcome> {
        let hash = self.calculate_hash(key);
        let mask = self.capacity - 1;
        let mut first_free = None;

        for i in 0..self.probe_limit {
            let idx = (hash + i * i) & mask;

            if let Some(ref entry) = self.entries[idx] {
                if entry.key == *key {
                    return Ok(self.entries[idx].as_mut().unwrap());
                }
            } else {
                if first_free.is_none() {
                    first_free = Some(idx);
                }
                break;
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
                reassembly: None,
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
    fn test_tcp_reassembly_ooo() {
        let pool = ForensicScratchpadPool::new();
        let mut rb = ReassemblyBuffer::new(1000);
        
        // Logical offset 50 starts at seq 1050
        rb.insert(1050, b"WORLD", &pool).unwrap();
        // Logical offset 0 starts at seq 1000
        rb.insert(1000, b"HELLO", &pool).unwrap();
        
        // We have two discontiguous segments: [1000, 1005) and [1050, 1055)
        // Note: Total reassembled bytes is 10, but they are sparse.
        assert_eq!(rb.len(), 10);
        assert_eq!(rb.get_contiguous(0, 5).unwrap(), b"HELLO");
        assert_eq!(rb.get_contiguous(50, 5).unwrap(), b"WORLD");
    }
}
