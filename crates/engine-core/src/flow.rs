use crate::scratchpad::{ForensicScratchpadPool, ScratchpadGuard, ScratchpadTier};
use crate::{FlowOutcome, FlowState, LogicalByteView};
use std::net::IpAddr;

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
struct SparseInterval<'a> {
    seq_start: u32,
    len: usize,
    slot: ScratchpadGuard<'a>,
}

/// Manages discontiguous TCP segments for a single flow.
pub struct ReassemblyBuffer<'a> {
    intervals: Vec<SparseInterval<'a>>,
    max_fragments: usize,
    max_window: u32,
    total_bytes: usize,
    pub base_seq: u32,
}

impl<'a> ReassemblyBuffer<'a> {
    pub fn new(base_seq: u32) -> Self {
        Self {
            intervals: Vec::with_capacity(8),
            max_fragments: 8,
            max_window: 64 * 1024,
            total_bytes: 0,
            base_seq,
        }
    }

    /// Ingests a new TCP segment using First-Writer-Wins policy.
    pub fn insert(
        &mut self,
        seq: u32,
        data: &[u8],
        pool: &'a ForensicScratchpadPool,
    ) -> Result<(), FlowOutcome> {
        const MAX_PRE_ANCHOR_BYTES: u32 = 1024;
        const MAX_UNCOVERED_SPANS: usize = 9;

        if seq >= self.base_seq {
            if seq - self.base_seq > self.max_window {
                return Err(FlowOutcome::ObfuscatedNetworkEnvelope);
            }
        } else if self.base_seq - seq > MAX_PRE_ANCHOR_BYTES {
            return Err(FlowOutcome::ObfuscatedNetworkEnvelope);
        }

        let seq_end = seq.wrapping_add(data.len() as u32);
        let mut spans = [(0u32, 0u32); MAX_UNCOVERED_SPANS];
        let mut span_count = 1;
        spans[0] = (seq, seq_end);

        // Subtract already-owned ranges and keep only uncovered spans.
        for interval in &self.intervals {
            let int_start = interval.seq_start;
            let int_end = int_start.wrapping_add(interval.len as u32);
            let mut next_spans = [(0u32, 0u32); MAX_UNCOVERED_SPANS];
            let mut next_count = 0;

            for idx in 0..span_count {
                let (span_start, span_end) = spans[idx];
                if span_start >= span_end {
                    continue;
                }

                let overlap_start = span_start.max(int_start);
                let overlap_end = span_end.min(int_end);

                if overlap_start >= overlap_end {
                    next_spans[next_count] = (span_start, span_end);
                    next_count += 1;
                    continue;
                }

                if span_start < overlap_start {
                    next_spans[next_count] = (span_start, overlap_start);
                    next_count += 1;
                }

                if overlap_end < span_end {
                    next_spans[next_count] = (overlap_end, span_end);
                    next_count += 1;
                }
            }

            spans = next_spans;
            span_count = next_count;

            if span_count == 0 {
                return Ok(());
            }
        }

        if self.intervals.len() + span_count > self.max_fragments {
            return Err(FlowOutcome::ExceededFragmentBudget);
        }

        for idx in 0..span_count {
            let (span_start, span_end) = spans[idx];
            let src_offset = span_start.wrapping_sub(seq) as usize;
            let span_len = (span_end - span_start) as usize;
            let slot = pool
                .acquire(ScratchpadTier::Tier1)
                .ok_or(FlowOutcome::FingerprintSuppressedByBackpressure)?;

            let len = span_len.min(slot.len());
            unsafe {
                let dst = slot.as_ptr() as *mut u8;
                std::ptr::copy_nonoverlapping(
                    data[src_offset..src_offset + len].as_ptr(),
                    dst,
                    len,
                );
            }

            self.intervals.push(SparseInterval {
                seq_start: span_start,
                len,
                slot,
            });
            self.total_bytes += len;
        }

        self.intervals.sort_by_key(|i| i.seq_start);
        Ok(())
    }
}

impl<'a> LogicalByteView for ReassemblyBuffer<'a> {
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

            if start_diff < 0x10000 && end_diff < 0x10000 {
                let inner_offset = start_diff as usize;
                return Some(&interval.slot[inner_offset..inner_offset + len]);
            }
        }
        None
    }

    fn copy_to(&self, offset: usize, dst: &mut [u8]) -> usize {
        let mut bytes_copied = 0;
        let target_seq = self.base_seq.wrapping_add(offset as u32);
        let end_seq = target_seq.wrapping_add(dst.len() as u32);

        // Intervals are sorted by sequence.
        for interval in &self.intervals {
            let int_start = interval.seq_start;
            let int_end = int_start.wrapping_add(interval.len as u32);

            // [overlap_start, overlap_end)
            let overlap_start = if target_seq > int_start {
                target_seq
            } else {
                int_start
            };
            let overlap_end = if end_seq < int_end { end_seq } else { int_end };

            if overlap_start < overlap_end {
                let dst_offset =
                    overlap_start.wrapping_sub(self.base_seq.wrapping_add(offset as u32)) as usize;
                let src_offset = overlap_start.wrapping_sub(int_start) as usize;
                let copy_len = (overlap_end - overlap_start) as usize;

                dst[dst_offset..dst_offset + copy_len]
                    .copy_from_slice(&interval.slot[src_offset..src_offset + copy_len]);
                bytes_copied += copy_len;
            }
        }
        bytes_copied
    }
}

/// Core state and reassembly metadata for a single TCP flow.
pub struct FlowEntry<'a> {
    pub key: FlowKey,
    pub state: FlowState,
    pub last_timestamp_ns: u64,
    pub timeout_ns: u64,
    pub reassembly: Option<ReassemblyBuffer<'a>>,
}

impl<'a> FlowEntry<'a> {
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
            FlowState::SynAckSeen if ack => self.state = FlowState::EstablishedTracking,
            _ => {}
        }

        None
    }

    pub fn process_payload(
        &mut self,
        seq: u32,
        data: &[u8],
        pool: &'a ForensicScratchpadPool,
    ) -> Option<FlowOutcome> {
        if data.is_empty() {
            return None;
        }

        if self.state == FlowState::EstablishedTracking {
            self.state = FlowState::ClientHelloIncomplete;
            self.reassembly = Some(ReassemblyBuffer::new(seq));
        }

        if let Some(ref mut rb) = self.reassembly {
            match rb.insert(seq, data, pool) {
                Ok(_) => {
                    let mut buf = [0u8; 5];
                    if rb.copy_to(0, &mut buf) == 5 && &buf == b"HELLO" {
                        self.state = FlowState::Fingerprinted;
                        return Some(FlowOutcome::Fingerprinted);
                    }
                    None
                }
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

pub struct TimingWheel {
    buckets: Vec<Vec<usize>>,
    current_tick: u64,
    tick_duration_ns: u64,
    num_buckets: usize,
}

impl TimingWheel {
    pub fn new(num_buckets: usize, tick_ns: u64) -> Self {
        Self {
            buckets: (0..num_buckets).map(|_| Vec::new()).collect(),
            current_tick: 0,
            tick_duration_ns: tick_ns,
            num_buckets,
        }
    }

    pub fn schedule(&mut self, flow_idx: usize, timeout_ns: u64, now_ns: u64) -> usize {
        let ticks = timeout_ns / self.tick_duration_ns;
        let bucket_idx = ((now_ns / self.tick_duration_ns) + ticks) as usize % self.num_buckets;
        self.buckets[bucket_idx].push(flow_idx);
        bucket_idx
    }

    pub fn advance(&mut self, now_ns: u64) -> Vec<usize> {
        let target_tick = now_ns / self.tick_duration_ns;
        let mut potential_expired = Vec::new();

        while self.current_tick < target_tick {
            self.current_tick += 1;
            let bucket_idx = self.current_tick as usize % self.num_buckets;
            potential_expired.extend(self.buckets[bucket_idx].drain(..));
        }

        potential_expired
    }
}

pub struct FlowMap<'a> {
    entries: Vec<Option<FlowEntry<'a>>>,
    capacity: usize,
    probe_limit: usize,
    count: usize,
    wheel: TimingWheel,
    default_timeout_ns: u64,
}

impl<'a> FlowMap<'a> {
    pub fn new(capacity: usize) -> Self {
        let actual_capacity = capacity.next_power_of_two();
        Self {
            entries: (0..actual_capacity).map(|_| None).collect(),
            capacity: actual_capacity,
            probe_limit: 16,
            count: 0,
            wheel: TimingWheel::new(4096, 10_000_000),
            default_timeout_ns: 100_000_000,
        }
    }

    pub fn acquire(
        &mut self,
        key: &FlowKey,
        now_ns: u64,
    ) -> Result<&mut FlowEntry<'a>, FlowOutcome> {
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
            self.wheel.schedule(idx, self.default_timeout_ns, now_ns);
            self.entries[idx] = Some(FlowEntry {
                key: *key,
                state: FlowState::SynSeen,
                last_timestamp_ns: now_ns,
                timeout_ns: self.default_timeout_ns,
                reassembly: None,
            });
            return Ok(self.entries[idx].as_mut().unwrap());
        }

        Err(FlowOutcome::CollisionDropped)
    }

    pub fn get_state(&self, key: &FlowKey) -> Option<FlowState> {
        let hash = self.calculate_hash(key);
        let mask = self.capacity - 1;
        for i in 0..self.probe_limit {
            let idx = (hash + i * i) & mask;
            if let Some(ref entry) = self.entries[idx] {
                if entry.key == *key {
                    return Some(entry.state);
                }
            } else {
                break;
            }
        }
        None
    }

    pub fn process_packet(
        &mut self,
        key: &FlowKey,
        flags: u8,
        seq: u32,
        data: &[u8],
        now_ns: u64,
        pool: &'a ForensicScratchpadPool,
    ) -> Option<FlowOutcome> {
        let entry_idx = {
            let hash = self.calculate_hash(key);
            let mask = self.capacity - 1;
            let mut found_idx = None;
            for i in 0..self.probe_limit {
                let idx = (hash + i * i) & mask;
                if let Some(ref entry) = self.entries[idx] {
                    if entry.key == *key {
                        found_idx = Some(idx);
                        break;
                    }
                } else {
                    break;
                }
            }
            found_idx
        };

        let outcome = if let Some(idx) = entry_idx {
            let entry = self.entries[idx].as_mut().unwrap();
            let flag_outcome = entry.process_tcp_flags(flags, now_ns);
            if flag_outcome.is_some() {
                flag_outcome
            } else {
                entry.process_payload(seq, data, pool)
            }
        } else {
            let syn = (flags & 0x02) != 0;
            if syn {
                match self.acquire(key, now_ns) {
                    Ok(_) => None,
                    Err(e) => Some(e),
                }
            } else {
                None
            }
        };

        if let Some(idx) = entry_idx {
            if let Some(ref entry) = self.entries[idx] {
                if matches!(entry.state, FlowState::Aborted | FlowState::Fingerprinted) {
                    self.entries[idx] = None;
                    self.count -= 1;
                }
            }
        }

        outcome
    }

    pub fn cleanup_expired(&mut self, now_ns: u64) -> Vec<FlowOutcome> {
        let potential_indices = self.wheel.advance(now_ns);
        let mut outcomes = Vec::new();

        for idx in potential_indices {
            let deadline = if let Some(ref entry) = self.entries[idx] {
                if matches!(
                    entry.state,
                    FlowState::Aborted | FlowState::Fingerprinted | FlowState::Expired
                ) {
                    None
                } else {
                    Some(entry.last_timestamp_ns + entry.timeout_ns)
                }
            } else {
                None
            };

            if let Some(dl) = deadline {
                if now_ns >= dl {
                    self.entries[idx] = None;
                    self.count -= 1;
                    outcomes.push(FlowOutcome::IncompleteTimedOut);
                } else {
                    let remaining = dl - now_ns;
                    self.wheel.schedule(idx, remaining, now_ns);
                }
            }
        }

        outcomes
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
        rb.insert(1050, b"WORLD", &pool).unwrap();
        rb.insert(1000, b"HELLO", &pool).unwrap();
        assert_eq!(rb.len(), 10);
        let mut buf = [0u8; 10];
        rb.copy_to(0, &mut buf);
        assert_eq!(&buf[0..5], b"HELLO");
    }

    #[test]
    fn test_partial_overlap_keeps_first_writer_and_appends_uncovered_suffix() {
        let pool = ForensicScratchpadPool::new();
        let mut rb = ReassemblyBuffer::new(1000);

        rb.insert(1000, &[b'A'; 100], &pool).unwrap();
        rb.insert(1050, &[b'B'; 100], &pool).unwrap();

        let mut overlap = [0u8; 1];
        let mut suffix = [0u8; 1];
        assert_eq!(rb.copy_to(50, &mut overlap), 1);
        assert_eq!(rb.copy_to(100, &mut suffix), 1);
        assert_eq!(overlap[0], b'A');
        assert_eq!(suffix[0], b'B');
    }

    #[test]
    fn test_immediate_terminal_eviction() {
        let pool = ForensicScratchpadPool::new();
        let mut map = FlowMap::new(16);
        let key = mock_key(1234);
        map.process_packet(&key, 0x02, 0, &[], 1000, &pool);
        assert_eq!(map.count, 1);
        map.process_packet(&key, 0x04, 0, &[], 2000, &pool);
        assert_eq!(map.count, 0);
    }
}
