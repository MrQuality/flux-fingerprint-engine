/// Zero-copy abstraction for packet data derived from hardware-backed buffers.
///
/// This trait is the foundational contract between ingestion drivers (AF_XDP, DPDK)
/// and the core processing engine.
pub trait PacketView {
    /// Returns the hardware or simulated timestamp in nanoseconds.
    fn timestamp_ns(&self) -> u64;

    /// Returns a borrowed slice of the raw packet data.
    /// This must not involve heap allocation or hidden memcpy (LC_001).
    fn data(&self) -> &[u8];

    /// Returns the ingress interface index if available.
    fn ingress_ifindex(&self) -> Option<u32> {
        None
    }

    /// Returns the RSS queue ID if available.
    fn rss_queue_id(&self) -> Option<u16> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stats_alloc::{Region, StatsAlloc, INSTRUMENTED_SYSTEM};
    use std::alloc::System;

    #[global_allocator]
    static ALLOC: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

    struct MockPacket<'a> {
        data: &'a [u8],
        ts: u64,
    }

    impl<'a> PacketView for MockPacket<'a> {
        fn timestamp_ns(&self) -> u64 {
            self.ts
        }
        fn data(&self) -> &[u8] {
            self.data
        }
    }

    #[test]
    fn test_packet_view_integrity() {
        let raw = [0u8; 64];
        let pkt = MockPacket {
            data: &raw,
            ts: 12345,
        };

        assert_eq!(pkt.data().len(), 64);
        assert_eq!(pkt.timestamp_ns(), 12345);
        assert_eq!(pkt.ingress_ifindex(), None);
    }

    #[test]
    fn test_zero_allocation_hot_path() {
        let reg = Region::new(ALLOC);
        let raw = [0u8; 1024];

        for i in 0..100 {
            let pkt = MockPacket {
                data: &raw,
                ts: i as u64,
            };
            let _ = pkt.data();
            let _ = pkt.timestamp_ns();
        }

        let change = reg.change();
        assert_eq!(
            change.allocations, 0,
            "Heap allocations detected in PacketView hot path!"
        );
    }
}
