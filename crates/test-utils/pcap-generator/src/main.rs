use anyhow::Result;
use flux_pcap_generator::write_pcap;

fn create_ipv6_extension_evasion() -> Vec<u8> {
    let mut pkt = vec![0u8; 200];
    pkt[12] = 0x86;
    pkt[13] = 0xDD; // IPv6
    pkt[14 + 6] = 0; // Next Header: Hop-by-Hop

    let mut offset = 14 + 40;
    for _ in 0..9 {
        // 9 extensions (limit is 8)
        if offset + 8 > pkt.len() {
            break;
        }
        pkt[offset] = 0; // Next Header: Hop-by-Hop
        pkt[offset + 1] = 0; // Hdr Ext Len: 0 (8 bytes total)
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
        &format!(
            "{}tests/fixtures/pcaps/ipv6_extension_evasion.pcap",
            base_path
        ),
        vec![(2000, create_ipv6_extension_evasion())],
    )?;

    println!("Generated adversarial PCAP fixtures.");
    Ok(())
}
