use anyhow::Result;
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use std::fs::{self, File};
use std::time::Duration;

pub fn write_pcap(path: &str, packets: Vec<(u64, Vec<u8>)>) -> Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = std::path::Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }

    let file = File::create(path)?;
    let header = PcapHeader::default();
    let mut writer = PcapWriter::with_header(file, header)?;

    for (ts_ns, data) in packets {
        let ts = Duration::from_nanos(ts_ns);
        let packet = PcapPacket::new(ts, data.len() as u32, &data);
        writer.write_packet(&packet)?;
    }
    Ok(())
}
