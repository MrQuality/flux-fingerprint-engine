use pcap_file::pcap::{PcapWriter, PcapHeader, PcapPacket};
use std::fs::File;
use std::time::Duration;
use anyhow::Result;

pub fn write_pcap(path: &str, packets: Vec<(u64, Vec<u8>)>) -> Result<()> {
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

fn main() -> Result<()> {
    // TASK-301 baseline
    write_pcap("tests/fixtures/pcaps/baseline_empty.pcap", vec![
        (1000, vec![0u8; 64]) // Dummy packet
    ])?;
    
    Ok(())
}
