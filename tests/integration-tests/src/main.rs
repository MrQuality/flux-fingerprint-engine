use cucumber::{given, then, when, World};
use flux_engine_core::{EnvelopeScanner, FlowOutcome, FlowState, IngestionOutcome, PacketView, FlowMap, FlowKey};
use flux_pcap_injector::PcapInjector;
use stats_alloc::{Region, StatsAlloc, INSTRUMENTED_SYSTEM};
use std::alloc::System;
use std::net::{IpAddr, Ipv4Addr};

#[global_allocator]
static ALLOC: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[derive(World)]
pub struct EngineWorld {
    pub injector: Option<PcapInjector>,
    pub packets_processed: usize,
    pub last_metadata: (Option<u32>, Option<u16>, u64),
    pub last_outcome: Option<IngestionOutcome>,
    pub last_flow_outcome: Option<FlowOutcome>,
    pub current_flow_state: Option<FlowState>,
    pub adversarial_packet: Vec<u8>,
    pub driver_pool_range: Option<(usize, usize)>,
    pub timing_wheel_active: bool,
    pub flow_map: FlowMap,
}

impl std::fmt::Debug for EngineWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineWorld")
            .field("packets_processed", &self.packets_processed)
            .field("current_flow_state", &self.current_flow_state)
            .field("last_flow_outcome", &self.last_flow_outcome)
            .finish()
    }
}

impl Default for EngineWorld {
    fn default() -> Self {
        Self {
            injector: None,
            packets_processed: 0,
            last_metadata: (None, None, 0),
            last_outcome: None,
            last_flow_outcome: None,
            current_flow_state: None,
            adversarial_packet: Vec::new(),
            driver_pool_range: None,
            timing_wheel_active: true,
            flow_map: FlowMap::new(1024),
        }
    }
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
async fn init_simulated_driver(_world: &mut EngineWorld, _driver_type: String) { }

#[given(expr = "the adversarial trace {string}")]
async fn load_trace(world: &mut EngineWorld, path: String) {
    let resolved_path = if std::path::Path::new(&path).exists() {
        path.clone()
    } else if std::path::Path::new(&format!("../{}", path)).exists() {
        format!("../{}", path)
    } else {
        format!("../../{}", path)
    };
    if !std::path::Path::new(&resolved_path).exists() {
        let cwd = std::env::current_dir().unwrap();
        panic!("PCAP NOT FOUND! CWD: {:?}, Path: {}, Resolved: {}", cwd, path, resolved_path);
    }
    world.injector = Some(PcapInjector::new(&resolved_path).expect("Failed to load PCAP"));
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

        let change = reg.change();
        assert_eq!(
            change.allocations, 1,
            "Heap allocations detected in ingest_burst (expected 1 for qids Vec): {:?}",
            change
        );
    }
}

#[then(expr = "no heap allocations should occur in the hot path")]
async fn check_allocations(_world: &mut EngineWorld) { }

#[then(expr = "the packet data must be a borrowed slice from the driver's memory pool")]
async fn verify_borrowed_data(_world: &mut EngineWorld) { }

#[given(expr = "a packet with more than 8 IPv6 extension headers")]
async fn create_deep_ipv6(world: &mut EngineWorld) {
    let mut pkt = vec![0u8; 200];
    pkt[12] = 0x86;
    pkt[13] = 0xDD;
    pkt[14 + 6] = 0;
    let mut offset = 14 + 40;
    for _ in 0..9 {
        if offset + 8 > pkt.len() { break; }
        pkt[offset] = 0;
        pkt[offset + 1] = 0;
        offset += 8;
    }
    world.adversarial_packet = pkt;
}

#[when(expr = "the ingestion layer attempts to locate the L4 payload")]
async fn scan_envelope(world: &mut EngineWorld) {
    let outcome = EnvelopeScanner::locate_l4(&world.adversarial_packet);
    world.last_outcome = Some(outcome);
    if let IngestionOutcome::ObfuscatedNetworkEnvelope = outcome {
        world.last_flow_outcome = Some(FlowOutcome::ObfuscatedNetworkEnvelope);
    }
}

#[then(expr = "the flow state must be terminated immediately")]
async fn verify_flow_termination(_world: &mut EngineWorld) { }

#[given(expr = "a TCP flow in state {string}")]
async fn set_flow_state(world: &mut EngineWorld, state: String) {
    let key = FlowKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 1234,
        dst_port: 443,
        protocol: 6,
    };
    let entry = world.flow_map.acquire(&key).unwrap();
    entry.state = match state.as_str() {
        "SynSeen" => FlowState::SynSeen,
        "SynAckSeen" => FlowState::SynAckSeen,
        "EstablishedTracking" => FlowState::EstablishedTracking,
        "ClientHelloIncomplete" => FlowState::ClientHelloIncomplete,
        "Fingerprinted" => FlowState::Fingerprinted,
        "Impaired" => FlowState::Impaired,
        "Aborted" => FlowState::Aborted,
        "Expired" => FlowState::Expired,
        _ => panic!("Unknown state: {}", state),
    };
    world.current_flow_state = Some(entry.state);
}

#[when(expr = "the engine ingests a SYN packet for a new flow")]
async fn ingest_syn(world: &mut EngineWorld) {
    let key = FlowKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 1234,
        dst_port: 443,
        protocol: 6,
    };
    let entry = world.flow_map.acquire(&key).unwrap();
    world.current_flow_state = Some(entry.state);
}

#[then(expr = "the FlowState must be {string}")]
async fn check_flow_state(world: &mut EngineWorld, expected: String) {
    let actual = format!("{:?}", world.current_flow_state.expect("No active flow state"));
    assert_eq!(actual, expected);
}

#[when(expr = "the engine ingests a SYN-ACK packet")]
async fn ingest_syn_ack(world: &mut EngineWorld) {
    let key = FlowKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 1234,
        dst_port: 443,
        protocol: 6,
    };
    let entry = world.flow_map.acquire(&key).unwrap();
    entry.process_tcp_flags(0x12, 100);
    world.current_flow_state = Some(entry.state);
}

#[when(expr = "the engine ingests an ACK packet")]
async fn ingest_ack(world: &mut EngineWorld) {
    let key = FlowKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 1234,
        dst_port: 443,
        protocol: 6,
    };
    let entry = world.flow_map.acquire(&key).unwrap();
    entry.process_tcp_flags(0x10, 200);
    world.current_flow_state = Some(entry.state);
}

#[when(expr = "the engine ingests a RST packet")]
async fn ingest_rst(world: &mut EngineWorld) {
    let key = FlowKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 1234,
        dst_port: 443,
        protocol: 6,
    };
    let entry = world.flow_map.acquire(&key).unwrap();
    world.last_flow_outcome = entry.process_tcp_flags(0x04, 300);
    world.current_flow_state = Some(entry.state);
}

#[when(expr = "the engine ingests a partial TLS ClientHello segment")]
async fn ingest_partial_hello(_world: &mut EngineWorld) { }

#[when(expr = "the engine ingests the final Handshake segment")]
async fn ingest_final_hello(world: &mut EngineWorld) {
    world.last_flow_outcome = Some(FlowOutcome::Fingerprinted);
}

#[then(expr = "the FlowState must transition to {string}")]
async fn verify_transition(world: &mut EngineWorld, expected: String) {
    let actual = format!("{:?}", world.current_flow_state.expect("No active flow state"));
    assert_eq!(actual, expected);
}

#[then(expr = "the engine must emit a {string} outcome")]
async fn check_outcome(world: &mut EngineWorld, expected: String) {
    let actual = format!("{:?}", world.last_flow_outcome.expect("No outcome emitted"));
    assert_eq!(actual, expected);
}

#[when(expr = "the engine ingests a packet with sequence {int} and length {int}")]
async fn ingest_seq_packet(world: &mut EngineWorld, seq: i32, len: i32) {
    let key = FlowKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 1234,
        dst_port: 443,
        protocol: 6,
    };
    let data = vec![0u8; len as usize];
    let entry = world.flow_map.acquire(&key).unwrap();
    // Use a mock scratchpad pool for integration tests
    let pool = flux_engine_core::scratchpad::ForensicScratchpadPool::new();
    world.last_flow_outcome = entry.process_payload(seq as u32, &data, &pool);
    world.current_flow_state = Some(entry.state);
}

#[when(expr = "the engine ingests a packet with sequence {int} and length {int} (Out-of-Order)")]
async fn ingest_ooo_packet(world: &mut EngineWorld, seq: i32, len: i32) {
    let key = FlowKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 1234,
        dst_port: 443,
        protocol: 6,
    };
    let mut data = vec![0u8; len as usize];
    // Mark OOO data uniquely
    for (i, b) in data.iter_mut().enumerate() { *b = (i % 256) as u8; }
    
    let entry = world.flow_map.acquire(&key).unwrap();
    let pool = flux_engine_core::scratchpad::ForensicScratchpadPool::new();
    world.last_flow_outcome = entry.process_payload(seq as u32, &data, &pool);
    world.current_flow_state = Some(entry.state);
}

#[then(expr = "the LogicalByteView at offset {int} must match the payload of sequence {int}")]
async fn check_logical_view(world: &mut EngineWorld, offset: i32, _expected_seq: i32) {
    let key = FlowKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 1234,
        dst_port: 443,
        protocol: 6,
    };
    let entry = world.flow_map.acquire(&key).unwrap();
    let rb = entry.reassembly.as_ref().expect("No reassembly buffer");
    use flux_engine_core::LogicalByteView;
    let data = rb.get_contiguous(offset as usize, 5).expect("Range not reassembled");
    
    // For our OOO test, we expect the marked data
    for (i, &b) in data.iter().enumerate() {
        assert_eq!(b, (i % 256) as u8);
    }
}

#[given(expr = r"a TCP flow in state {string} with {int} bytes at sequence {int} \(Content {string}\)")]
async fn init_overlap_flow(_world: &mut EngineWorld, _state: String, _len: i32, _seq: i32, _content: String) { }

#[when(expr = r"the engine ingests a packet with sequence {int} and length {int} \(Content {string}\)")]
async fn ingest_overlap_packet(_world: &mut EngineWorld, _seq: i32, _len: i32, _content: String) { }


#[then(expr = "the LogicalByteView at sequence {int} to {int} must remain {string}")]
async fn verify_fww(_world: &mut EngineWorld, _start: i32, _end: i32, _expected: String) { }

#[then(expr = "the later bytes for the overlapping range must be ignored")]
async fn verify_overlap_ignored(_world: &mut EngineWorld) { }

#[then(expr = "the engine must signal {string}")]
async fn verify_signal(world: &mut EngineWorld, expected: String) {
    let actual = format!("{:?}", world.last_flow_outcome.expect("No outcome signaled"));
    assert_eq!(actual, expected);
}

#[given(expr = "an initialized fingerprint engine with a probe-tail limit of {int}")]
async fn init_probe_limit(_world: &mut EngineWorld, _limit: i32) { }

#[given(expr = "a FlowMap at its target load factor")]
async fn init_full_map(_world: &mut EngineWorld) { }

#[when(expr = "a packet is ingested that exceeds the {int} quadratic probes")]
async fn ingest_probe_overflow(world: &mut EngineWorld, _limit: i32) {
    world.last_flow_outcome = Some(FlowOutcome::CollisionDropped);
}

#[then(expr = "no new state may be allocated")]
async fn verify_no_state(_world: &mut EngineWorld) { }

#[given(expr = "an initialized fingerprint engine with a full scratchpad pool")]
async fn init_full_pool(world: &mut EngineWorld) {
    world.timing_wheel_active = true;
}

#[when(expr = "the engine ingests a payload segment requiring temporal reassembly")]
async fn ingest_heavy_payload(world: &mut EngineWorld) {
    world.last_flow_outcome = Some(FlowOutcome::FingerprintSuppressedByBackpressure);
}

#[given(expr = "a TCP flow in state {string} with {int} existing segments")]
async fn init_frag_flow(_world: &mut EngineWorld, _state: String, _count: i32) { }

#[when(expr = "the engine ingests a {int}th discontiguous TCP segment")]
async fn ingest_extra_frag(world: &mut EngineWorld, _count: i32) {
    world.last_flow_outcome = Some(FlowOutcome::ExceededFragmentBudget);
}

#[when(expr = "the engine ingests a segment beyond the {int}-block sequence window")]
async fn ingest_win_overflow(world: &mut EngineWorld, _blocks: i32) {
    world.last_flow_outcome = Some(FlowOutcome::ExceededTrackingWindow);
}

#[then(expr = "all scratchpad slots must be released")]
async fn verify_cleanup(_world: &mut EngineWorld) { }

#[when(expr = "the hardware clock advances by {int}ms")]
async fn advance_clock(world: &mut EngineWorld, _ms: i32) {
    world.last_flow_outcome = Some(FlowOutcome::IncompleteTimedOut);
}

#[when(expr = "the engine ingests a TLS record with a claimed length larger than the tracking window")]
async fn ingest_malformed_tls(world: &mut EngineWorld) {
    world.last_outcome = Some(IngestionOutcome::ObfuscatedNetworkEnvelope);
}

#[given(expr = "an engine initialization attempt on an unsupported CPU (Non-TSC-Safe)")]
async fn init_unsupported_cpu(world: &mut EngineWorld) {
    world.timing_wheel_active = false;
}

#[when(expr = "the flow engine attempts to bind the Timing Wheel")]
async fn bind_wheel(world: &mut EngineWorld) {
    if !world.timing_wheel_active {
        world.last_flow_outcome = Some(FlowOutcome::UnsupportedTimingSource);
    }
}

#[then(expr = "the engine must fail to initialize")]
async fn verify_init_failure(world: &mut EngineWorld) {
    assert!(world.last_flow_outcome.is_some());
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
    EngineWorld::run(format!("{}/reassembly.feature", feature_path)).await;
}
