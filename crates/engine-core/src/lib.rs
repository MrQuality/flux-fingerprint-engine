/// Zero-copy abstraction for packet data derived from hardware-backed buffers.
pub trait PacketView {
    /// Returns the hardware or simulated timestamp in nanoseconds.
    fn timestamp_ns(&self) -> u64;

    /// Returns a borrowed slice of the raw packet data.
    /// This must not involve heap allocation or hidden memcpy.
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
