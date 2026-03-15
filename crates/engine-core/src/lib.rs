pub mod scratchpad;

/// Zero-copy abstraction for packet data derived from hardware-backed buffers.
pub trait PacketView {
    fn timestamp_ns(&self) -> u64;
    fn data(&self) -> &[u8];
    fn ingress_ifindex(&self) -> Option<u32>;
    fn rss_queue_id(&self) -> Option<u16>;
}

/// Metadata extracted from the protocol envelope.
#[derive(Debug, PartialEq)]
pub enum IngestionOutcome {
    Success { l4_offset: usize },
    ObfuscatedNetworkEnvelope, // Too many IPv6 extensions
    UnsupportedProtocol,
}

/// A bounded, single-pass scanner for the network envelope.
pub struct EnvelopeScanner;

impl EnvelopeScanner {
    const MAX_IPV6_EXT_HEADERS: u8 = 8;

    /// Traverses the L3 headers to locate the L4 (TCP) offset.
    pub fn locate_l4(packet: &[u8]) -> IngestionOutcome {
        if packet.len() < 14 { return IngestionOutcome::UnsupportedProtocol; }
        
        let eth_type = u16::from_be_bytes([packet[12], packet[13]]);
        
        match eth_type {
            0x0800 => { // IPv4
                if packet.len() < 34 { return IngestionOutcome::UnsupportedProtocol; }
                let ihl = (packet[14] & 0x0F) as usize * 4;
                IngestionOutcome::Success { l4_offset: 14 + ihl }
            }
            0x86DD => { // IPv6
                let mut offset = 14 + 40; 
                let mut next_header = packet[14 + 6];
                let mut ext_count = 0;
                
                while Self::is_ipv6_extension(next_header) {
                    if ext_count >= Self::MAX_IPV6_EXT_HEADERS {
                        return IngestionOutcome::ObfuscatedNetworkEnvelope;
                    }
                    if packet.len() < offset + 8 { return IngestionOutcome::UnsupportedProtocol; }
                    
                    let ext_len = (packet[offset + 1] as usize + 1) * 8;
                    next_header = packet[offset];
                    offset += ext_len;
                    ext_count += 1;
                }
                
                IngestionOutcome::Success { l4_offset: offset }
            }
            _ => IngestionOutcome::UnsupportedProtocol,
        }
    }

    fn is_ipv6_extension(header_type: u8) -> bool {
        match header_type {
            0 | 43 | 44 | 51 | 60 | 135 | 139 | 140 => true,
            _ => false,
        }
    }
}

/// Utility for verifying RSS entropy and 4-tuple distribution.
pub struct RssValidator;

impl RssValidator {
    /// CA-004: Audits distribution to ensure no single queue handles > 70% of a diverse burst.
    pub fn verify_entropy(packets: &[impl PacketView]) -> bool {
        if packets.len() < 10 { return true; } 
        
        let mut queue_counts = std::collections::HashMap::new();
        
        for pkt in packets {
            if let Some(qid) = pkt.rss_queue_id() {
                *queue_counts.entry(qid).or_insert(0) += 1;
            }
        }
        
        if queue_counts.len() < 2 {
            return false; 
        }

        let max_allowed = (packets.len() as f64 * 0.7) as usize;
        for count in queue_counts.values() {
            if *count > max_allowed {
                return false; 
            }
        }
        
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockPacket<'a> {
        data: &'a [u8],
        ts: u64,
    }

    impl<'a> PacketView for MockPacket<'a> {
        fn timestamp_ns(&self) -> u64 { self.ts }
        fn data(&self) -> &[u8] { self.data }
        fn ingress_ifindex(&self) -> Option<u32> { None }
        fn rss_queue_id(&self) -> Option<u16> { None }
    }

    #[test]
    fn test_ipv4_l4_location() {
        let mut pkt = vec![0u8; 34];
        pkt[12] = 0x08; pkt[13] = 0x00; 
        pkt[14] = 0x45; 
        assert_eq!(EnvelopeScanner::locate_l4(&pkt), IngestionOutcome::Success { l4_offset: 34 });
    }

    #[test]
    fn test_ipv6_extension_limit() {
        let mut pkt = vec![0u8; 200];
        pkt[12] = 0x86; pkt[13] = 0xDD; 
        pkt[14+6] = 0; 
        
        let mut offset = 14 + 40;
        for _ in 0..9 { 
            if offset + 8 > pkt.len() { break; }
            pkt[offset] = 0; 
            pkt[offset+1] = 0; 
            offset += 8;
        }
        
        assert_eq!(EnvelopeScanner::locate_l4(&pkt), IngestionOutcome::ObfuscatedNetworkEnvelope);
    }
}
