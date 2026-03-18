use anyhow::{Context, Result};
use flux_engine_core::PacketView;
use pcap_file::pcap::PcapReader;
use std::fs::File;

/// A synthetic NIC driver that maps PCAP packets to the PacketView trait.
#[derive(Debug)]
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

            let timestamp_ns = pkt.timestamp.as_nanos() as u64;
            offsets.push((start, end - start, timestamp_ns));
        }

        Ok(Self { raw_data, offsets })
    }

    pub fn get_packet(&self, index: usize) -> Option<BorrowedPacketView<'_>> {
        self.offsets.get(index).map(|&(start, len, ts)| {
            BorrowedPacketView {
                data: &self.raw_data[start..start + len],
                timestamp_ns: ts,
                ifindex: Some(1),
                queue_id: Some((index % 4) as u16), // Simulate diverse RSS distribution
            }
        })
    }

    pub fn packet_count(&self) -> usize {
        self.offsets.len()
    }

    pub fn raw_data_ptr(&self) -> *const u8 {
        self.raw_data.as_ptr()
    }

    pub fn raw_data_len(&self) -> usize {
        self.raw_data.len()
    }
}

#[derive(Debug)]
pub struct BorrowedPacketView<'a> {
    data: &'a [u8],
    timestamp_ns: u64,
    ifindex: Option<u32>,
    queue_id: Option<u16>,
}

impl<'a> PacketView for BorrowedPacketView<'a> {
    fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }
    fn data(&self) -> &[u8] {
        self.data
    }
    fn ingress_ifindex(&self) -> Option<u32> {
        self.ifindex
    }
    fn rss_queue_id(&self) -> Option<u16> {
        self.queue_id
    }
}
