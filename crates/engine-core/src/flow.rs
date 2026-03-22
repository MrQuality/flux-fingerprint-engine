use crate::scratchpad::{ForensicScratchpadPool, ScratchpadGuard, ScratchpadTier};
use crate::{FlowOutcome, FlowState, LogicalByteView};
use std::net::IpAddr;

/// Bidirectional 5-tuple for flow identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub a_ip: IpAddr,
    pub b_ip: IpAddr,
    pub a_port: u16,
    pub b_port: u16,
    pub protocol: u8,
}

impl FlowKey {
    pub fn from_packet(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        if (src_ip, src_port) < (dst_ip, dst_port) {
            Self {
                a_ip: src_ip,
                b_ip: dst_ip,
                a_port: src_port,
                b_port: dst_port,
                protocol,
            }
        } else {
            Self {
                a_ip: dst_ip,
                b_ip: src_ip,
                a_port: dst_port,
                b_port: src_port,
                protocol,
            }
        }
    }
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
    /// The sequence number anchoring offset 0 of the logical view.
    pub base_seq: Option<u32>,
    /// Length of the strictly contiguous prefix starting from base_seq.
    pub contiguous_len: usize,
}

impl<'a> ReassemblyBuffer<'a> {
    pub fn new() -> Self {
        Self {
            intervals: Vec::with_capacity(8),
            max_fragments: 8,
            max_window: 64 * 1024,
            base_seq: None,
            contiguous_len: 0,
        }
    }

    /// Ingests a new TCP segment using First-Writer-Wins policy.
    pub fn insert(
        &mut self,
        seq: u32,
        data: &[u8],
        pool: &'a ForensicScratchpadPool,
    ) -> Result<(), FlowOutcome> {
        if data.is_empty() {
            return Ok(());
        }

        if self.base_seq.is_none() {
            self.base_seq = Some(seq);
        }

        let base = self.base_seq.unwrap();
        let seq_end = seq.wrapping_add(data.len() as u32);

        // Limit checking
        let diff = seq.wrapping_sub(base);
        if diff < 0x80000000 {
            if diff > self.max_window {
                return Err(FlowOutcome::ExceededTrackingWindow);
            }
        } else {
            let pre_diff = base.wrapping_sub(seq);
            if pre_diff > 1024 {
                return Err(FlowOutcome::ExceededTrackingWindow);
            }
            self.base_seq = Some(seq);
        }

        let mut spans = [(0u32, 0u32); 16];
        let mut span_count = 1;
        spans[0] = (seq, seq_end);

        for interval in &self.intervals {
            let int_start = interval.seq_start;
            let int_end = int_start.wrapping_add(interval.len as u32);
            let mut next_spans = [(0u32, 0u32); 16];
            let mut next_count = 0;

            for idx in 0..span_count {
                let (s_start, s_end) = spans[idx];

                let intersection_start = if s_start.wrapping_sub(int_start) < 0x80000000 {
                    s_start.max(int_start)
                } else {
                    int_start
                };
                let intersection_end = if s_end.wrapping_sub(int_end) < 0x80000000 {
                    int_end
                } else {
                    s_end.min(int_end)
                };

                if intersection_end.wrapping_sub(intersection_start) < 0x80000000 {
                    if s_start != intersection_start {
                        next_spans[next_count] = (s_start, intersection_start);
                        next_count += 1;
                    }
                    if intersection_end != s_end {
                        next_spans[next_count] = (intersection_end, s_end);
                        next_count += 1;
                    }
                } else {
                    next_spans[next_count] = (s_start, s_end);
                    next_count += 1;
                }
            }
            spans = next_spans;
            span_count = next_count;
            if span_count == 0 { return Ok(()); }
        }

        if self.intervals.len() + span_count > self.max_fragments {
            return Err(FlowOutcome::ExceededFragmentBudget);
        }

        for i in 0..span_count {
            let (s_start, s_end) = spans[i];
            let len = s_end.wrapping_sub(s_start) as usize;
            let slot = pool.acquire(ScratchpadTier::Tier1).ok_or(FlowOutcome::FingerprintSuppressedByBackpressure)?;
            
            let src_offset = s_start.wrapping_sub(seq) as usize;
            unsafe {
                std::ptr::copy_nonoverlapping(data[src_offset..src_offset+len].as_ptr(), slot.as_ptr() as *mut u8, len);
            }
            self.intervals.push(SparseInterval { seq_start: s_start, len, slot });
        }

        self.intervals.sort_by_key(|i| i.seq_start);
        self.recalculate_contiguous();
        Ok(())
    }

    fn recalculate_contiguous(&mut self) {
        let base = match self.base_seq {
            Some(b) => b,
            None => return,
        };
        let mut next_expected = base;
        for interval in &self.intervals {
            if interval.seq_start == next_expected {
                next_expected = next_expected.wrapping_add(interval.len as u32);
            } else if interval.seq_start.wrapping_sub(next_expected) < 0x80000000 {
                break;
            }
        }
        self.contiguous_len = next_expected.wrapping_sub(base) as usize;
    }
}

impl<'a> LogicalByteView for ReassemblyBuffer<'a> {
    fn len(&self) -> usize {
        self.contiguous_len
    }

    fn get_contiguous(&self, offset: usize, len: usize) -> Option<&[u8]> {
        let base = self.base_seq?;
        let target_start = base.wrapping_add(offset as u32);
        let target_end = target_start.wrapping_add(len as u32);

        for interval in &self.intervals {
            let int_start = interval.seq_start;
            let int_end = int_start.wrapping_add(interval.len as u32);

            let starts_after = target_start.wrapping_sub(int_start) < 0x80000000;
            let ends_before = int_end.wrapping_sub(target_end) < 0x80000000;

            if starts_after && ends_before {
                let inner_offset = target_start.wrapping_sub(int_start) as usize;
                return Some(&interval.slot[inner_offset..inner_offset + len]);
            }
        }
        None
    }

    fn copy_to(&self, offset: usize, dst: &mut [u8]) -> usize {
        let base = match self.base_seq {
            Some(b) => b,
            None => return 0,
        };
        let avail = self.contiguous_len.saturating_sub(offset);
        let to_copy = dst.len().min(avail);
        if to_copy == 0 { return 0; }

        let target_start = base.wrapping_add(offset as u32);
        let target_end = target_start.wrapping_add(to_copy as u32);

        let mut copied = 0;
        for interval in &self.intervals {
            let int_start = interval.seq_start;
            let int_end = int_start.wrapping_add(interval.len as u32);

            let intersection_start = if target_start.wrapping_sub(int_start) < 0x80000000 {
                target_start.max(int_start)
            } else {
                int_start
            };
            let intersection_end = if target_end.wrapping_sub(int_end) < 0x80000000 {
                int_end
            } else {
                target_end.min(int_end)
            };

            if intersection_end.wrapping_sub(intersection_start) < 0x80000000 {
                let src_off = intersection_start.wrapping_sub(int_start) as usize;
                let dst_off = intersection_start.wrapping_sub(target_start) as usize;
                let c_len = intersection_end.wrapping_sub(intersection_start) as usize;
                dst[dst_off..dst_off + c_len].copy_from_slice(&interval.slot[src_off..src_off + c_len]);
                copied += c_len;
            }
        }
        copied
    }
}

pub struct FlowEntry<'a> {
    pub key: FlowKey,
    pub client_addr: (IpAddr, u16),
    pub state: FlowState,
    pub client_isn: u32,
    pub server_isn: u32,
    pub last_timestamp_ns: u64,
    pub timeout_ns: u64,
    pub reassembly: Option<ReassemblyBuffer<'a>>,
}

impl<'a> FlowEntry<'a> {
    pub fn teardown(&mut self) {
        self.reassembly = None;
    }

    pub fn direction(&self, src_ip: IpAddr, src_port: u16) -> Direction {
        if (src_ip, src_port) == self.client_addr {
            Direction::ClientToServer
        } else {
            Direction::ServerToClient
        }
    }

    pub fn process_packet(
        &mut self,
        direction: Direction,
        flags: u8,
        seq: u32,
        payload: &[u8],
        ts_ns: u64,
        pool: &'a ForensicScratchpadPool,
    ) -> Option<FlowOutcome> {
        self.last_timestamp_ns = ts_ns;

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

        match direction {
            Direction::ClientToServer => {
                let ack = (flags & 0x10) != 0;
                if ack && self.state == FlowState::SynAckSeen {
                    self.state = FlowState::EstablishedTracking;
                }

                if !payload.is_empty() && (self.state == FlowState::EstablishedTracking || self.state == FlowState::ClientHelloIncomplete) {
                    return self.process_payload(seq, payload, pool);
                }
            }
            Direction::ServerToClient => {
                let syn = (flags & 0x02) != 0;
                let ack = (flags & 0x10) != 0;

                if syn && ack && self.state == FlowState::SynSeen {
                    self.state = FlowState::SynAckSeen;
                    self.server_isn = seq;
                }
            }
        }

        None
    }

    fn process_payload(
        &mut self,
        seq: u32,
        payload: &[u8],
        pool: &'a ForensicScratchpadPool,
    ) -> Option<FlowOutcome> {
        if self.state == FlowState::EstablishedTracking {
            // Lazy Allocation check
            struct DirectView<'b>(&'b [u8]);
            impl<'b> LogicalByteView for DirectView<'b> {
                fn len(&self) -> usize { self.0.len() }
                fn get_contiguous(&self, o: usize, l: usize) -> Option<&[u8]> {
                    if o + l <= self.0.len() { Some(&self.0[o..o+l]) } else { None }
                }
                fn copy_to(&self, o: usize, d: &mut [u8]) -> usize {
                    let l = d.len().min(self.0.len().saturating_sub(o));
                    d[..l].copy_from_slice(&self.0[o..o+l]);
                    l
                }
            }

            match crate::TlsParser::parse_record(&DirectView(payload)) {
                Some(FlowOutcome::Fingerprinted) => {
                    self.state = FlowState::Fingerprinted;
                    return Some(FlowOutcome::Fingerprinted);
                }
                Some(outcome) => {
                    self.state = FlowState::Impaired;
                    return Some(outcome);
                }
                None => {
                    self.state = FlowState::ClientHelloIncomplete;
                    self.reassembly = Some(ReassemblyBuffer::new());
                }
            }
        }

        if let Some(ref mut rb) = self.reassembly {
            if let Err(outcome) = rb.insert(seq, payload, pool) {
                self.state = FlowState::Impaired;
                return Some(outcome);
            }

            match crate::TlsParser::parse_record(rb) {
                Some(FlowOutcome::Fingerprinted) => {
                    self.state = FlowState::Fingerprinted;
                    Some(FlowOutcome::Fingerprinted)
                }
                Some(outcome) => {
                    self.state = FlowState::Impaired;
                    Some(outcome)
                }
                None => None,
            }
        } else {
            None
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

pub enum Slot<'a> {
    Empty,
    Occupied(FlowEntry<'a>),
    Tombstone,
}

/// A lockless-oriented hierarchical timing wheel for O(1) flow expiration.
/// 
/// MP-001 Section 6.4: Reaping is an O(1) byproduct of packet processing.
pub struct TimingWheel {
    buckets: Vec<Vec<usize>>,
    resolution_ns: u64,
    horizon_buckets: usize,
    current_bucket: usize,
    last_advanced_ns: u64,
}

impl TimingWheel {
    pub fn new(capacity: usize, resolution_ns: u64, horizon_buckets: usize) -> Self {
        Self {
            buckets: (0..horizon_buckets).map(|_| Vec::with_capacity(capacity / horizon_buckets)).collect(),
            resolution_ns,
            horizon_buckets,
            current_bucket: 0,
            last_advanced_ns: 0,
        }
    }

    pub fn schedule(&mut self, entry_idx: usize, now_ns: u64, timeout_ns: u64) {
        if self.last_advanced_ns == 0 {
            self.last_advanced_ns = now_ns;
        }
        let delta = timeout_ns / self.resolution_ns;
        let bucket_offset = delta as usize;
        let target_bucket = (self.current_bucket + bucket_offset).min(self.horizon_buckets - 1);
        self.buckets[target_bucket].push(entry_idx);
    }

    pub fn advance(&mut self, now_ns: u64) -> Vec<usize> {
        if self.last_advanced_ns == 0 {
            self.last_advanced_ns = now_ns;
        }

        let elapsed = now_ns.saturating_sub(self.last_advanced_ns);
        let ticks = (elapsed / self.resolution_ns) as usize;
        let mut expired = Vec::new();

        for _ in 0..=ticks.min(self.horizon_buckets - 1) {
            let bucket_data = std::mem::take(&mut self.buckets[self.current_bucket]);
            expired.extend(bucket_data);
            self.current_bucket = (self.current_bucket + 1) % self.horizon_buckets;
        }

        self.last_advanced_ns += (ticks as u64) * self.resolution_ns;
        expired
    }
}

pub struct FlowMap<'a> {
    entries: Vec<Slot<'a>>,
    capacity: usize,
    probe_limit: usize,
    count: usize,
    default_timeout_ns: u64,
    timing_wheel: TimingWheel,
}

impl<'a> FlowMap<'a> {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.next_power_of_two();
        Self {
            entries: (0..cap).map(|_| Slot::Empty).collect(),
            capacity: cap,
            probe_limit: 16,
            count: 0,
            default_timeout_ns: 100_000_000,
            timing_wheel: TimingWheel::new(cap, 10_000_000, 128), // 10ms resolution, 1.28s horizon
        }
    }

    pub fn entries(&self) -> &[Slot<'a>] {
        &self.entries
    }

    fn calculate_hash(&self, key: &FlowKey) -> usize {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut s = DefaultHasher::new();
        key.hash(&mut s);
        s.finish() as usize
    }

    pub fn ingest_packet(
        &mut self,
        packet: &[u8],
        now_ns: u64,
        pool: &'a ForensicScratchpadPool,
    ) -> Option<FlowOutcome> {
        let outcome = crate::EnvelopeScanner::locate_l4(packet);
        match outcome {
            crate::IngestionOutcome::Success { l4_offset } => {
                // MP-005: Locate L4 and extract 5-tuple + sequence + flags + payload
                if packet.len() < l4_offset + 20 {
                    return Some(FlowOutcome::UnsupportedPacketShape);
                }

                let eth_type = u16::from_be_bytes([packet[12], packet[13]]);
                let (src_ip, dst_ip, protocol) = if eth_type == 0x0800 {
                    (
                        IpAddr::V4(std::net::Ipv4Addr::new(packet[26], packet[27], packet[28], packet[29])),
                        IpAddr::V4(std::net::Ipv4Addr::new(packet[30], packet[31], packet[32], packet[33])),
                        packet[23],
                    )
                } else if eth_type == 0x86DD {
                    (
                        IpAddr::V6(std::net::Ipv6Addr::from([
                            packet[22], packet[23], packet[24], packet[25], packet[26], packet[27],
                            packet[28], packet[29], packet[30], packet[31], packet[32], packet[33],
                            packet[34], packet[35], packet[36], packet[37],
                        ])),
                        IpAddr::V6(std::net::Ipv6Addr::from([
                            packet[38], packet[39], packet[40], packet[41], packet[42], packet[43],
                            packet[44], packet[45], packet[46], packet[47], packet[48], packet[49],
                            packet[50], packet[51], packet[52], packet[53],
                        ])),
                        packet[14 + 6], // Proto in IPv6 fixed header
                    )
                } else {
                    return Some(FlowOutcome::UnsupportedPacketShape);
                };

                let src_port = u16::from_be_bytes([packet[l4_offset], packet[l4_offset + 1]]);
                let dst_port = u16::from_be_bytes([packet[l4_offset + 2], packet[l4_offset + 3]]);
                let seq = u32::from_be_bytes([packet[l4_offset + 4], packet[l4_offset + 5], packet[l4_offset + 6], packet[l4_offset + 7]]);
                let data_offset = ((packet[l4_offset + 12] >> 4) as usize) * 4;
                let flags = packet[l4_offset + 13];
                let payload = if packet.len() >= l4_offset + data_offset {
                    &packet[l4_offset + data_offset..]
                } else {
                    &[]
                };

                self.process_packet(src_ip, dst_ip, src_port, dst_port, protocol, flags, seq, payload, now_ns, pool)
            }
            crate::IngestionOutcome::ObfuscatedNetworkEnvelope => {
                Some(FlowOutcome::ObfuscatedNetworkEnvelope)
            }
            _ => Some(FlowOutcome::UnsupportedPacketShape),
        }
    }

    pub fn process_packet(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        flags: u8,
        seq: u32,
        payload: &[u8],
        now_ns: u64,
        pool: &'a ForensicScratchpadPool,
    ) -> Option<FlowOutcome> {
        let key = FlowKey::from_packet(src_ip, dst_ip, src_port, dst_port, protocol);
        let hash = self.calculate_hash(&key);
        let mask = self.capacity - 1;
        let mut slot_idx = None;
        let mut first_tombstone = None;

        for i in 0..self.probe_limit {
            let idx = (hash + i * i) & mask;
            match &self.entries[idx] {
                Slot::Occupied(e) if e.key == key => {
                    slot_idx = Some(idx);
                    break;
                }
                Slot::Tombstone if first_tombstone.is_none() => {
                    first_tombstone = Some(idx);
                }
                Slot::Empty => {
                    if slot_idx.is_none() {
                        slot_idx = first_tombstone.or(Some(idx));
                    }
                    break;
                }
                _ => {}
            }
        }

        if let Some(idx) = slot_idx {
            match &mut self.entries[idx] {
                Slot::Occupied(ref mut entry) => {
                    let dir = entry.direction(src_ip, src_port);
                    let res = entry.process_packet(dir, flags, seq, payload, now_ns, pool);
                    if entry.state.is_terminal() {
                        entry.teardown();
                        let final_res = res;
                        self.entries[idx] = Slot::Tombstone;
                        self.count -= 1;
                        return final_res;
                    }
                    res
                }
                Slot::Empty | Slot::Tombstone if (flags & 0x02) != 0 => {
                    let mut entry = FlowEntry {
                        key,
                        client_addr: (src_ip, src_port),
                        state: FlowState::SynSeen,
                        client_isn: seq,
                        server_isn: 0,
                        last_timestamp_ns: now_ns,
                        timeout_ns: self.default_timeout_ns,
                        reassembly: None,
                    };
                    self.count += 1;
                    let res = entry.process_packet(Direction::ClientToServer, flags, seq, payload, now_ns, pool);
                    self.entries[idx] = Slot::Occupied(entry);
                    self.timing_wheel.schedule(idx, now_ns, self.default_timeout_ns);
                    res
                }
                _ => None,
            }
        } else {
            Some(FlowOutcome::CollisionDropped)
        }
    }

    pub fn get_state(&self, key: &FlowKey) -> Option<FlowState> {
        let hash = self.calculate_hash(key);
        let mask = self.capacity - 1;
        for i in 0..self.probe_limit {
            let idx = (hash + i * i) & mask;
            match &self.entries[idx] {
                Slot::Occupied(e) if e.key == *key => return Some(e.state),
                Slot::Tombstone => continue,
                Slot::Empty => break,
                _ => {}
            }
        }
        None
    }

    pub fn cleanup_expired(&mut self, now_ns: u64) -> Vec<FlowOutcome> {
        let mut outcomes = Vec::new();
        let expired_indices = self.timing_wheel.advance(now_ns);

        for idx in expired_indices {
            if let Slot::Occupied(ref entry) = self.entries[idx] {
                // Double-check because it might have been updated or already terminal
                if now_ns > entry.last_timestamp_ns + entry.timeout_ns {
                    if let Slot::Occupied(mut e) = std::mem::replace(&mut self.entries[idx], Slot::Tombstone) {
                        e.teardown();
                        self.count -= 1;
                        outcomes.push(FlowOutcome::IncompleteTimedOut);
                    }
                } else {
                    // Reschedule if it's still active but wasn't expired yet
                    let remaining = (entry.last_timestamp_ns + entry.timeout_ns).saturating_sub(now_ns);
                    self.timing_wheel.schedule(idx, now_ns, remaining);
                }
            }
        }
        outcomes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn mock_key(port: u16) -> FlowKey {
        FlowKey::from_packet(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port,
            443,
            6,
        )
    }

    #[test]
    fn test_tcp_reassembly_ooo() {
        let pool = ForensicScratchpadPool::new();
        let mut rb = ReassemblyBuffer::new();
        rb.insert(1050, b"WORLD", &pool).unwrap();
        rb.insert(1000, b"HELLO", &pool).unwrap();
        assert_eq!(rb.len(), 5); 
        let mut buf = [0u8; 10];
        rb.copy_to(0, &mut buf);
        assert_eq!(&buf[0..5], b"HELLO");
    }

    #[test]
    fn test_overlap_fww() {
        let pool = ForensicScratchpadPool::new();
        let mut rb = ReassemblyBuffer::new();
        rb.insert(1000, b"AAAA", &pool).unwrap();
        rb.insert(1002, b"BBBB", &pool).unwrap(); 
        let mut buf = [0u8; 6];
        rb.copy_to(0, &mut buf);
        assert_eq!(&buf, b"AAAABB"); 
    }
}
