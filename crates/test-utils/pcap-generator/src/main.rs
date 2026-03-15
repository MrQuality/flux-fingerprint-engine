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

fn create_ipv6_extension_evasion() -> Vec<u8> {
    let mut pkt = vec![0u8; 200];
    pkt[12] = 0x86; pkt[13] = 0xDD; // IPv6
    pkt[14+6] = 0; // Next Header: Hop-by-Hop
    
    let mut offset = 14 + 40;
    for _ in 0..9 { // 9 extensions (limit is 8)
        if offset + 8 > pkt.len() { break; }
        pkt[offset] = 0; // Next Header: Hop-by-Hop
        pkt[offset+1] = 0; // Hdr Ext Len: 0 (8 bytes total)
        offset += 8;
    }
    pkt
}

fn main() -> Result<()> {
    // Determine base path (assume running from workspace root or crate root)
    let base_path = if std::path::Path::new("tests").exists() {
        ""
    } else {
        "../../../"
    };

    // 1. Baseline
    write_pcap(
        &format!("{}tests/fixtures/pcaps/baseline_empty.pcap", base_path),
        vec![(1000, vec![0u8; 64])],
    )?;

    // 2. IPv6 Extension Evasion (CA-04)
    write_pcap(
        &format!("{}tests/fixtures/pcaps/ipv6_extension_evasion.pcap", base_path),
        vec![(2000, create_ipv6_extension_evasion())],
    )?;

    println!("Generated adversarial PCAP fixtures.");
    Ok(())
}
