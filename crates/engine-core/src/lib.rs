pub mod flow;
pub mod scratchpad;

pub use flow::{FlowEntry, FlowKey, FlowMap};

/// Zero-copy abstraction for packet data derived from hardware-backed buffers.
pub trait PacketView {
    fn timestamp_ns(&self) -> u64;
    fn data(&self) -> &[u8];
    fn ingress_ifindex(&self) -> Option<u32>;
    fn rss_queue_id(&self) -> Option<u16>;
}

/// Metadata extracted from the protocol envelope.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum IngestionOutcome {
    Success { l4_offset: usize },
    ObfuscatedNetworkEnvelope, // Too many IPv6 extensions
    MalformedProtocolHeader,   // IPv4 IHL error or truncated extensions
    UnsupportedProtocol,
}

/// Canonical TCP states defined in MP-001.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum FlowState {
    SynSeen,
    SynAckSeen,
    EstablishedTracking,
    ClientHelloIncomplete,
    Fingerprinted,
    Impaired,
    Aborted,
    Expired,
}

impl FlowState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Fingerprinted | Self::Impaired | Self::Aborted | Self::Expired)
    }
}
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum FlowOutcome {
    Fingerprinted,
    IncompleteAwaitingMoreData,
    IncompleteTimedOut,
    MalformedTls,
    NotClientHello,
    UnsupportedPacketShape,
    QueueDropped,
    CollisionDropped,
    StateEvicted,
    AbortedByFin,
    AbortedByRst,
    UnsupportedMidstreamFlow,
    ExceededFragmentBudget,
    ExceededTrackingWindow,
    UnsupportedTimingSource,
    AsymmetricVisibilityLoss,
    ObfuscatedNetworkEnvelope,
    ECHVisibilityLimited,
    FingerprintSuppressedByBackpressure,
}

/// Zero-copy abstraction for reading discontiguous reassembled segments.
pub trait LogicalByteView {
    /// Total bytes currently reassembled in logical sequence.
    fn len(&self) -> usize;
    /// Borrow a specific byte range if contiguous, or None if it spans slots.
    fn get_contiguous(&self, offset: usize, len: usize) -> Option<&[u8]>;
    /// Copy logical range into a caller-provided buffer (Fallback).
    fn copy_to(&self, offset: usize, dst: &mut [u8]) -> usize;
}

/// TLS Record types.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TlsRecordType {
    Handshake = 22,
    Alert = 21,
    ChangeCipherSpec = 20,
    ApplicationData = 23,
    Heartbeat = 24,
    Unknown,
}

impl From<u8> for TlsRecordType {
    fn from(v: u8) -> Self {
        match v {
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            24 => Self::Heartbeat,
            _ => Self::Unknown,
        }
    }
}

/// TLS Handshake types.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TlsHandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
    Unknown,
}

impl From<u8> for TlsHandshakeType {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::ClientHello,
            2 => Self::ServerHello,
            4 => Self::NewSessionTicket,
            5 => Self::EndOfEarlyData,
            8 => Self::EncryptedExtensions,
            11 => Self::Certificate,
            13 => Self::CertificateRequest,
            15 => Self::CertificateVerify,
            20 => Self::Finished,
            24 => Self::KeyUpdate,
            254 => Self::MessageHash,
            _ => Self::Unknown,
        }
    }
}

/// A zero-copy TLS parser operating on LogicalByteView.
pub struct TlsParser;

impl TlsParser {
    /// Parses the TLS Record header and determines the outcome.
    pub fn parse_record(view: &impl LogicalByteView) -> Option<FlowOutcome> {
        if view.len() < 5 {
            return None;
        }

        let mut header = [0u8; 5];
        view.copy_to(0, &mut header);

        let record_type = TlsRecordType::from(header[0]);
        let version = u16::from_be_bytes([header[1], header[2]]);
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;

        // MP-006: max_tls_record_size = 18,432
        if length > 18432 {
            return Some(FlowOutcome::MalformedTls);
        }

        // If the reassembly buffer hasn't even reached the claimed record length,
        // we must wait for more data.
        if view.len() < 5 + length {
            return None;
        }

        if record_type != TlsRecordType::Handshake {
            return Some(FlowOutcome::NotClientHello);
        }

        // TLS Handshake version must be >= 0x0301 (TLS 1.0) and <= 0x0304 (TLS 1.3)
        if version < 0x0301 || version > 0x0304 {
            return Some(FlowOutcome::MalformedTls);
        }

        if length < 4 {
            return Some(FlowOutcome::MalformedTls);
        }

        // MP-006: max_tls_handshake_size = 32,768
        if length > 32768 {
             return Some(FlowOutcome::MalformedTls);
        }

        // Need at least 4 bytes for Handshake Header
        if view.len() < 5 + 4 {
            return None;
        }

        let mut hs_header = [0u8; 4];
        view.copy_to(5, &mut hs_header);

        let hs_type = TlsHandshakeType::from(hs_header[0]);
        let hs_len =
            ((hs_header[1] as usize) << 16) | ((hs_header[2] as usize) << 8) | (hs_header[3] as usize);

        if hs_type != TlsHandshakeType::ClientHello {
            return Some(FlowOutcome::NotClientHello);
        }

        if hs_len > length - 4 {
            return Some(FlowOutcome::MalformedTls);
        }

        // Wait for full Handshake body if not yet reassembled
        if view.len() < 5 + 4 + hs_len {
            return None;
        }

        // The record length might be larger than the Handshake length (padding, or multiple HS messages)
        // But for ClientHello, it usually fills the record or is slightly less.
        // If we have the full HS message as claimed by hs_len, we proceed.

        // ECH Detection (Draft Implementation)
        if Self::detect_ech(view, 5 + 4, hs_len) {
            return Some(FlowOutcome::ECHVisibilityLimited);
        }

        Some(FlowOutcome::Fingerprinted)
    }

    fn detect_ech(view: &impl LogicalByteView, offset: usize, len: usize) -> bool {
        // Skip session ID, cipher suites, compression methods to find extensions.
        // Minimum CH size to have extensions is roughly 34 (Random) + 1 (SID) + 2 (CipherSuites) + 1 (Comp) = 38.
        if len < 38 {
            return false;
        }

        let mut pos = offset + 34; // Skip version (2) and random (32)

        // Session ID
        let mut sid_len_buf = [0u8; 1];
        if view.copy_to(pos, &mut sid_len_buf) != 1 {
            return false;
        }
        let sid_len = sid_len_buf[0] as usize;
        pos += 1 + sid_len;

        // Cipher Suites
        let mut cs_len_buf = [0u8; 2];
        if view.copy_to(pos, &mut cs_len_buf) != 2 {
            return false;
        }
        let cs_len = u16::from_be_bytes(cs_len_buf) as usize;
        pos += 2 + cs_len;

        // Compression Methods
        let mut cm_len_buf = [0u8; 1];
        if view.copy_to(pos, &mut cm_len_buf) != 1 {
            return false;
        }
        let cm_len = cm_len_buf[0] as usize;
        pos += 1 + cm_len;

        // Extensions
        if view.len() < pos + 2 {
            return false;
        }
        let mut ext_total_len_buf = [0u8; 2];
        view.copy_to(pos, &mut ext_total_len_buf);
        let ext_total_len = u16::from_be_bytes(ext_total_len_buf) as usize;
        pos += 2;

        let ext_end = pos + ext_total_len;
        while pos + 4 <= ext_end && pos + 4 <= view.len() {
            let mut ext_header = [0u8; 4];
            view.copy_to(pos, &mut ext_header);
            let ext_type = u16::from_be_bytes([ext_header[0], ext_header[1]]);
            let ext_len = u16::from_be_bytes([ext_header[2], ext_header[3]]) as usize;

            if ext_type == 0xfe0d {
                return true;
            }
            pos += 4 + ext_len;
        }

        false
    }
}

/// A bounded, single-pass scanner for the network envelope.
pub struct EnvelopeScanner;

impl EnvelopeScanner {
    const MAX_IPV6_EXT_HEADERS: u8 = 8;
    const MAX_IPV6_EXT_BYTES: usize = 128; // MP-001 bound

    /// Traverses the L3 headers to locate the L4 (TCP) offset.
    ///
    /// Enforces LC_003 (Fail-Closed) on malformed or adversarial headers.
    pub fn locate_l4(packet: &[u8]) -> IngestionOutcome {
        if packet.len() < 14 {
            return IngestionOutcome::UnsupportedProtocol;
        }

        let eth_type = u16::from_be_bytes([packet[12], packet[13]]);

        match eth_type {
            0x0800 => {
                // IPv4
                if packet.len() < 34 {
                    return IngestionOutcome::MalformedProtocolHeader;
                }
                let ihl = (packet[14] & 0x0F) as usize;
                if ihl < 5 {
                    return IngestionOutcome::MalformedProtocolHeader;
                }
                let l3_len = ihl * 4;
                if packet.len() < 14 + l3_len {
                    return IngestionOutcome::MalformedProtocolHeader;
                }
                IngestionOutcome::Success {
                    l4_offset: 14 + l3_len,
                }
            }
            0x86DD => {
                // IPv6
                if packet.len() < 14 + 40 {
                    return IngestionOutcome::MalformedProtocolHeader;
                }
                let mut offset = 14 + 40;
                let mut next_header = packet[14 + 6];
                let mut ext_count = 0;
                let mut ext_bytes = 0;

                while Self::is_ipv6_extension(next_header) {
                    if ext_count >= Self::MAX_IPV6_EXT_HEADERS {
                        return IngestionOutcome::ObfuscatedNetworkEnvelope;
                    }
                    if packet.len() < offset + 8 {
                        return IngestionOutcome::MalformedProtocolHeader;
                    }

                    let ext_len = (packet[offset + 1] as usize + 1) * 8;
                    if packet.len() < offset + ext_len {
                        return IngestionOutcome::MalformedProtocolHeader;
                    }

                    ext_bytes += ext_len;
                    if ext_bytes > Self::MAX_IPV6_EXT_BYTES {
                        return IngestionOutcome::ObfuscatedNetworkEnvelope;
                    }

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
        matches!(header_type, 0 | 43 | 44 | 51 | 60 | 135 | 139 | 140)
    }
}

/// Utility for verifying RSS entropy and 4-tuple distribution.
pub struct RssValidator;

impl RssValidator {
    /// CA-004: Audits distribution to ensure no single queue handles > 70% of a diverse burst.
    pub fn verify_entropy(packets: &[impl PacketView]) -> bool {
        if packets.len() < 10 {
            return true;
        }

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

    #[allow(dead_code)]
    struct MockPacket<'a> {
        _data: &'a [u8],
        _ts: u64,
    }

    impl<'a> PacketView for MockPacket<'a> {
        fn timestamp_ns(&self) -> u64 {
            self._ts
        }
        fn data(&self) -> &[u8] {
            self._data
        }
        fn ingress_ifindex(&self) -> Option<u32> {
            None
        }
        fn rss_queue_id(&self) -> Option<u16> {
            None
        }
    }

    #[test]
    fn test_ipv4_malformed_ihl() {
        let mut pkt = vec![0u8; 34];
        pkt[12] = 0x08;
        pkt[13] = 0x00;
        pkt[14] = 0x44; // IHL = 4 (invalid, min is 5)
        assert_eq!(
            EnvelopeScanner::locate_l4(&pkt),
            IngestionOutcome::MalformedProtocolHeader
        );
    }

    #[test]
    fn test_ipv6_truncated_extension() {
        let mut pkt = vec![0u8; 60];
        pkt[12] = 0x86;
        pkt[13] = 0xDD;
        pkt[14 + 6] = 0; // Hop-by-Hop
        pkt[14 + 40 + 1] = 10; // Claimed length 88 bytes, but pkt is only 60
        assert_eq!(
            EnvelopeScanner::locate_l4(&pkt),
            IngestionOutcome::MalformedProtocolHeader
        );
    }
}
