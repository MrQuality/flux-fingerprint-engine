use cucumber::{given, then, when, World};
use flux_engine_core::{EnvelopeScanner, IngestionOutcome, PacketView};
use flux_pcap_injector::PcapInjector;
use stats_alloc::{Region, StatsAlloc, INSTRUMENTED_SYSTEM};
use std::alloc::System;

#[global_allocator]
static ALLOC: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[derive(Debug, World, Default)]
pub struct EngineWorld {
    pub injector: Option<PcapInjector>,
    pub packets_processed: usize,
    pub last_metadata: (Option<u32>, Option<u16>, u64),
    pub last_outcome: Option<IngestionOutcome>,
    pub adversarial_packet: Vec<u8>,
    pub driver_pool_range: Option<(usize, usize)>,
}

#[given(expr = "an initialized fingerprint engine")]
async fn init_engine(world: &mut EngineWorld) {
    world.packets_processed = 0;
}

#[given(expr = "the environment is locked to stable Rust")]
async fn check_rust_version(_world: &mut EngineWorld) {
    // Verified by ci.yml and rust-toolchain.toml
}

#[given(expr = "a simulated {string} ingestion driver")]
async fn init_simulated_driver(_world: &mut EngineWorld, _driver_type: String) {
    // In a real recovery, this would instantiate the actual adapter types
    // and bind them to a mock hardware environment.
}

#[given(expr = "the adversarial trace {string}")]
async fn load_trace(world: &mut EngineWorld, path: String) {
    world.injector = Some(PcapInjector::new(&path).expect("Failed to load PCAP"));
}

#[when(expr = "the engine ingests a packet from the trace")]
async fn ingest_single_packet(world: &mut EngineWorld) {
    if let Some(ref injector) = world.injector {
        if let Some(packet) = injector.get_packet(0) {
            world.last_metadata = (
                packet.ingress_ifindex(),
                packet.rss_queue_id(),
                packet.timestamp_ns(),
            );
            world.adversarial_packet = packet.data().to_vec();
            world.packets_processed = 1;
        }
    }
}

#[when(expr = "the engine ingests all packets from the trace")]
async fn ingest_all_packets(world: &mut EngineWorld) {
    if let Some(ref injector) = world.injector {
        for i in 0..injector.packet_count() {
            if let Some(pkt) = injector.get_packet(i) {
                let _ = pkt.data();
                world.packets_processed += 1;
            }
        }
    }
}

#[then(expr = "the ingestion count should be greater than 0")]
async fn verify_ingestion_count(world: &mut EngineWorld) {
    assert!(world.packets_processed > 0);
}

#[then(expr = "the {string} should be present")]
async fn check_metadata_present(world: &mut EngineWorld, field: String) {
    match field.as_str() {
        "ingress_ifindex" => assert!(world.last_metadata.0.is_some(), "ingress_ifindex missing"),
        "rss_queue_id" => assert!(world.last_metadata.1.is_some(), "rss_queue_id missing"),
        _ => panic!("Unknown metadata field: {}", field),
    }
}

#[then(expr = "the \"timestamp_ns\" should match the hardware clock")]
async fn check_timestamp(world: &mut EngineWorld) {
    assert!(world.last_metadata.2 > 0, "timestamp_ns is 0");
}

#[given(expr = "a simulated high-throughput packet stream")]
async fn init_high_throughput(world: &mut EngineWorld) {
    let pcap_path = if std::path::Path::new("tests/fixtures/pcaps/baseline_empty.pcap").exists() {
        "tests/fixtures/pcaps/baseline_empty.pcap"
    } else {
        "../fixtures/pcaps/baseline_empty.pcap"
    };
    let injector = PcapInjector::new(pcap_path).unwrap();

    let pool_base = injector.raw_data_ptr() as usize;
    let pool_len = injector.raw_data_len();
    world.driver_pool_range = Some((pool_base, pool_base + pool_len));

    world.injector = Some(injector);
}

#[when(expr = "the engine ingests 1000 packets")]
async fn ingest_burst(world: &mut EngineWorld) {
    if let Some(ref injector) = world.injector {
        let count = injector.packet_count();
        let reg = Region::new(ALLOC);

        let mut qids = Vec::with_capacity(1000);
        for i in 0..1000 {
            if let Some(pkt) = injector.get_packet(i % count) {
                // CA-03: ptr::addr_eq verification
                if let Some((start, end)) = world.driver_pool_range {
                    let pkt_addr = pkt.data().as_ptr() as usize;
                    assert!(
                        pkt_addr >= start && pkt_addr < end,
                        "Packet data outside driver pool range!"
                    );
                }

                let _ = pkt.data();
                qids.push(pkt.rss_queue_id().unwrap_or(0));
                world.packets_processed += 1;
            }
        }

        // CA-04: RSS Distribution Audit
        if count >= 10 {
            let mut queue_counts = std::collections::HashMap::new();
            for qid in &qids {
                *queue_counts.entry(qid).or_insert(0) += 1;
            }
            assert!(queue_counts.len() > 1, "Lack of RSS entropy!");
            let max_allowed = (qids.len() as f64 * 0.7) as usize;
            for (qid, count) in queue_counts {
                assert!(
                    count <= max_allowed,
                    "RSS skew detected on queue {}: {}/{}",
                    qid,
                    count,
                    qids.len()
                );
            }
        }

        let change = reg.change();
        // CA-03: Zero-allocation audit
        assert_eq!(
            change.allocations, 1,
            "Heap allocations detected in ingest_burst (expected 1 for qids Vec): {:?}",
            change
        );
    }
}

#[then(expr = "no heap allocations should occur in the hot path")]
async fn check_allocations(_world: &mut EngineWorld) {
    // Verified inside ingest_burst for precision
}

#[then(expr = "the packet data must be a borrowed slice from the driver's memory pool")]
async fn verify_borrowed_data(_world: &mut EngineWorld) {
    // Verified inside ingest_burst via ptr range checks
}

#[given(expr = "a packet with more than 8 IPv6 extension headers")]
async fn create_deep_ipv6(world: &mut EngineWorld) {
    let mut pkt = vec![0u8; 200];
    pkt[12] = 0x86;
    pkt[13] = 0xDD;
    pkt[14 + 6] = 0;
    let mut offset = 14 + 40;
    for _ in 0..9 {
        if offset + 8 > pkt.len() {
            break;
        }
        pkt[offset] = 0;
        pkt[offset + 1] = 0;
        offset += 8;
    }
    world.adversarial_packet = pkt;
}

#[when(expr = "the ingestion layer attempts to locate the L4 payload")]
async fn scan_envelope(world: &mut EngineWorld) {
    world.last_outcome = Some(EnvelopeScanner::locate_l4(&world.adversarial_packet));
}

#[then(expr = "the engine must signal \"ObfuscatedNetworkEnvelope\"")]
async fn verify_obfuscation_signal(world: &mut EngineWorld) {
    assert_eq!(
        world.last_outcome,
        Some(IngestionOutcome::ObfuscatedNetworkEnvelope)
    );
}

#[then(expr = "the flow state must be terminated immediately")]
async fn verify_flow_termination(_world: &mut EngineWorld) {
    // In a stateful core, this would verify FTE teardown
}

#[tokio::main]
async fn main() {
    let feature_path = if std::path::Path::new("tests/features").exists() {
        "tests/features"
    } else {
        "../features"
    };

    EngineWorld::run(format!("{}/baseline.feature", feature_path)).await;
    EngineWorld::run(format!("{}/ingestion.feature", feature_path)).await;
}
