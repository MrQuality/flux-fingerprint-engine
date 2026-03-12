use flux_engine_core::PacketView;
use pcap_file::pcap::PcapReader;
use std::fs::File;
use anyhow::{Result, Context};

/// A synthetic NIC driver that maps PCAP packets to the PacketView trait.
/// 
/// Note: While the injector itself owns the raw_data Vec, the individual 
/// packets emitted are zero-copy views (BorrowedPacketView) into that buffer.
pub struct PcapInjector {
    raw_data: Vec<u8>,
    offsets: Vec<(usize, usize, u64)>, // (start, length, timestamp_ns)
}

impl PcapInjector {
    pub fn new(file_path: &str) -> Result<Self> {
        let file = File::open(file_path).context("Failed to open PCAP file")?;
        let mut reader = PcapReader::new(file).context("Failed to initialize PCAP reader")?;
        
        let mut raw_data = Vec::new();
        let mut offsets = Vec::new();
        
        while let Some(pkt) = reader.next_packet() {
            let pkt = pkt.context("Failed to read packet from PCAP")?;
            let start = raw_data.len();
            raw_data.extend_from_slice(&pkt.data);
            let end = raw_data.len();
            
            // Convert pcap timestamp to nanoseconds
            let timestamp_ns = pkt.timestamp.as_nanos() as u64;
            offsets.push((start, end - start, timestamp_ns));
        }
        
        Ok(Self { raw_data, offsets })
    }

    /// Returns a list of zero-copy views into the underlying PCAP buffer.
    pub fn packets(&self) -> Vec<BorrowedPacketView> {
        self.offsets.iter().map(|&(start, len, ts)| {
            BorrowedPacketView {
                data: &self.raw_data[start..start+len],
                timestamp_ns: ts,
            }
        }).collect()
    }
}

/// A zero-copy view of a single packet in the PCAP buffer.
pub struct BorrowedPacketView<'a> {
    data: &'a [u8],
    timestamp_ns: u64,
}

impl<'a> PacketView for BorrowedPacketView<'a> {
    fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }

    fn data(&self) -> &[u8] {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_copy_mapping() {
        // Placeholder for verification once fixtures are generated in TASK-304
    }
}
