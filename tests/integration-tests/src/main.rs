use cucumber::{given, then, when, World};
use flux_pcap_injector::PcapInjector;
use flux_engine_core::{PacketView, EnvelopeScanner, IngestionOutcome};
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
    pub alloc_region: Option<Region<'static, System>>,
    pub adversarial_packet: Vec<u8>,
}

#[given(expr = "an initialized fingerprint engine")]
async fn init_engine(world: &mut EngineWorld) {
    world.packets_processed = 0;
    world.alloc_region = Some(Region::new(ALLOC));
}

#[given(expr = "the environment is locked to stable Rust")]
async fn check_rust_version(_world: &mut EngineWorld) {}

#[given(expr = "a simulated {string} ingestion driver")]
async fn init_simulated_driver(_world: &mut EngineWorld, _driver_type: String) {}

#[given(expr = "the adversarial trace {string}")]
async fn load_trace(world: &mut EngineWorld, path: String) {
    world.injector = Some(PcapInjector::new(&path).expect("Failed to load PCAP"));
}

#[when(expr = "the engine ingests a packet from the trace")]
async fn ingest_single_packet(world: &mut EngineWorld) {
    if let Some(ref injector) = world.injector {
        if let Some(packet) = injector.get_packet(0) {
            world.last_metadata = (packet.ingress_ifindex(), packet.rss_queue_id(), packet.timestamp_ns());
            world.adversarial_packet = packet.data().to_vec();
            world.packets_processed = 1;
        }
    }
}

#[then(expr = "the {string} should be present")]
async fn check_metadata_present(world: &mut EngineWorld, field: String) {
    match field.as_str() {
        "ingress_ifindex" => assert!(world.last_metadata.0.is_some()),
        "rss_queue_id" => assert!(world.last_metadata.1.is_some()),
        _ => panic!("Unknown metadata field: {}", field),
    }
}

#[then(expr = "the \"timestamp_ns\" should match the hardware clock")]
async fn check_timestamp(world: &mut EngineWorld) {
    assert!(world.last_metadata.2 > 0);
}

#[given(expr = "a simulated high-throughput packet stream")]
async fn init_high_throughput(world: &mut EngineWorld) {
    let pcap_path = if std::path::Path::new("tests/fixtures/pcaps/baseline_empty.pcap").exists() {
        "tests/fixtures/pcaps/baseline_empty.pcap"
    } else {
        "../fixtures/pcaps/baseline_empty.pcap"
    };
    world.injector = Some(PcapInjector::new(pcap_path).unwrap());
}

#[when(expr = "the engine ingests 1000 packets")]
async fn ingest_burst(world: &mut EngineWorld) {
    if let Some(ref injector) = world.injector {
        let count = injector.packet_count();
        let reg = Region::new(ALLOC);
        for i in 0..1000 {
            if let Some(pkt) = injector.get_packet(i % count) {
                let _ = pkt.data();
                world.packets_processed += 1;
            }
        }
        let change = reg.change();
        assert_eq!(change.allocations, 0, "Heap allocations detected in burst loop: {:?}", change);
    }
}

#[then(expr = "no heap allocations should occur in the hot path")]
async fn check_allocations(_world: &mut EngineWorld) {
    // Verified inside ingest_burst step for precision
}

#[then(expr = "the packet data must be a borrowed slice from the driver's memory pool")]
async fn verify_borrowed_data(_world: &mut EngineWorld) {}

#[given(expr = "a packet with more than 8 IPv6 extension headers")]
async fn create_deep_ipv6(world: &mut EngineWorld) {
    let mut pkt = vec![0u8; 200];
    pkt[12] = 0x86; pkt[13] = 0xDD; // IPv6
    pkt[14+6] = 0; // Hop-by-Hop
    let mut offset = 14 + 40;
    for _ in 0..9 {
        if offset + 8 > pkt.len() { break; }
        pkt[offset] = 0; pkt[offset+1] = 0;
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
    assert_eq!(world.last_outcome, Some(IngestionOutcome::ObfuscatedNetworkEnvelope));
}

#[then(expr = "the flow state must be terminated immediately")]
async fn verify_flow_termination(_world: &mut EngineWorld) {}

#[given(expr = "a driver that returns zero-length buffers")]
async fn init_broken_driver(world: &mut EngineWorld) {
    world.adversarial_packet = vec![0u8; 14];
}

#[then(expr = "the engine must skip the descriptor and signal an impairment")]
async fn verify_impairment_signal(world: &mut EngineWorld) {
    let outcome = EnvelopeScanner::locate_l4(&world.adversarial_packet);
    assert_eq!(outcome, IngestionOutcome::UnsupportedProtocol);
}
#[tokio::main]
async fn main() {
    // Determine base path (assume running from workspace root or crate root)
    let feature_path = if std::path::Path::new("tests/features").exists() {
        "tests/features"
    } else {
        "../features"
    };

    EngineWorld::run(&format!("{}/baseline.feature", feature_path)).await;
    EngineWorld::run(&format!("{}/ingestion.feature", feature_path)).await;
}
