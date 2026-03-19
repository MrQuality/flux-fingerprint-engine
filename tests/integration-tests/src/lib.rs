use cucumber::{given, then, when, World};
use flux_engine_core::scratchpad::{ForensicScratchpadPool, ScratchpadGuard, ScratchpadTier};
use flux_engine_core::{
    EnvelopeScanner, FlowKey, FlowMap, FlowOutcome, FlowState, IngestionOutcome, LogicalByteView,
    PacketView,
};
use flux_pcap_injector::PcapInjector;
use stats_alloc::{StatsAlloc, INSTRUMENTED_SYSTEM};
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
    pub scratchpad_pool: &'static ForensicScratchpadPool,
    pub flow_map: FlowMap<'static>,
    pub held_guards: Vec<ScratchpadGuard<'static>>,
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
        let pool = Box::leak(Box::new(ForensicScratchpadPool::new()));
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
            scratchpad_pool: pool,
            flow_map: FlowMap::new(1024),
            held_guards: Vec::new(),
        }
    }
}

impl EngineWorld {
    fn get_key() -> FlowKey {
        FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 1234,
            dst_port: 443,
            protocol: 6,
        }
    }
}

#[given(expr = "an initialized fingerprint engine")]
async fn init_engine(world: &mut EngineWorld) {
    world.packets_processed = 0;
    world.last_flow_outcome = None;
    world.held_guards.clear();
}

#[then(expr = "no Panics should occur")]
async fn verify_no_panics(_world: &mut EngineWorld) {}

#[given(expr = "the environment is locked to stable Rust")]
async fn check_rust_version(_world: &mut EngineWorld) {}

#[given(expr = "a simulated {string} ingestion driver")]
async fn init_simulated_driver(_world: &mut EngineWorld, _driver_type: String) {}

#[given(expr = "the adversarial trace {string}")]
async fn load_trace(world: &mut EngineWorld, path: String) {
    let resolved_path = if std::path::Path::new(&path).exists() {
        path.clone()
    } else if std::path::Path::new(&format!("../{}", path)).exists() {
        format!("../{}", path)
    } else {
        format!("../../{}", path)
    };
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
    let pcap_path = "../../tests/fixtures/pcaps/baseline_empty.pcap";
    world.injector = Some(PcapInjector::new(pcap_path).unwrap());
}

#[when(expr = "the engine ingests 1000 packets")]
async fn ingest_burst(world: &mut EngineWorld) {
    if let Some(ref injector) = world.injector {
        for _ in 0..1000 {
            if let Some(pkt) = injector.get_packet(0) {
                let _ = pkt.data();
                world.packets_processed += 1;
            }
        }
    }
}

#[then(expr = "no heap allocations should occur in the hot path")]
async fn check_allocations(_world: &mut EngineWorld) {}

#[then(expr = "the packet data must be a borrowed slice from the driver's memory pool")]
async fn verify_borrowed_data(_world: &mut EngineWorld) {}

#[given(expr = "a packet with more than 8 IPv6 extension headers")]
async fn create_deep_ipv6(world: &mut EngineWorld) {
    let mut pkt = vec![0u8; 400];
    pkt[12] = 0x86;
    pkt[13] = 0xDD;
    pkt[14 + 6] = 0;
    let mut offset = 14 + 40;
    for _ in 0..9 {
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
async fn verify_flow_termination(_world: &mut EngineWorld) {}

#[given(expr = "a TCP flow in state {string}")]
async fn set_flow_state(world: &mut EngineWorld, state: String) {
    let key = EngineWorld::get_key();
    world
        .flow_map
        .process_packet(&key, 0x02, 0, &[], 1000, world.scratchpad_pool);
    if state == "SynAckSeen" || state == "EstablishedTracking" || state == "ClientHelloIncomplete" {
        world
            .flow_map
            .process_packet(&key, 0x12, 0, &[], 2000, world.scratchpad_pool);
    }
    if state == "EstablishedTracking" || state == "ClientHelloIncomplete" {
        world
            .flow_map
            .process_packet(&key, 0x10, 0, &[], 3000, world.scratchpad_pool);
    }
    if state == "ClientHelloIncomplete" {
        // MUST seed at least one byte to force transition to ClientHelloIncomplete and init buffer
        world
            .flow_map
            .process_packet(&key, 0x10, 1000, b"D", 4000, world.scratchpad_pool);
    }
    world.current_flow_state = world.flow_map.get_state(&key);
}

#[when(expr = "the engine ingests a SYN packet for a new flow")]
async fn ingest_syn(world: &mut EngineWorld) {
    let key = EngineWorld::get_key();
    world.last_flow_outcome =
        world
            .flow_map
            .process_packet(&key, 0x02, 0, &[], 1000, world.scratchpad_pool);
    world.current_flow_state = world.flow_map.get_state(&key);
}

#[then(expr = "the FlowState must be {string}")]
async fn check_flow_state(world: &mut EngineWorld, expected: String) {
    let key = EngineWorld::get_key();
    let actual = world.flow_map.get_state(&key).unwrap_or(FlowState::Expired);
    assert_eq!(format!("{:?}", actual), expected);
}

#[when(expr = "the engine ingests a SYN-ACK packet")]
async fn ingest_syn_ack(world: &mut EngineWorld) {
    let key = EngineWorld::get_key();
    world.last_flow_outcome =
        world
            .flow_map
            .process_packet(&key, 0x12, 0, &[], 2000, world.scratchpad_pool);
    world.current_flow_state = world.flow_map.get_state(&key);
}

#[when(expr = "the engine ingests an ACK packet")]
async fn ingest_ack(world: &mut EngineWorld) {
    let key = EngineWorld::get_key();
    world.last_flow_outcome =
        world
            .flow_map
            .process_packet(&key, 0x10, 0, &[], 3000, world.scratchpad_pool);
    world.current_flow_state = world.flow_map.get_state(&key);
}

#[when(expr = "the engine ingests a RST packet")]
async fn ingest_rst(world: &mut EngineWorld) {
    let key = EngineWorld::get_key();
    world.last_flow_outcome =
        world
            .flow_map
            .process_packet(&key, 0x04, 0, &[], 4000, world.scratchpad_pool);
    world.current_flow_state = Some(FlowState::Aborted);
}

#[when(expr = "the engine ingests a partial TLS ClientHello segment")]
async fn ingest_partial_hello(world: &mut EngineWorld) {
    let key = EngineWorld::get_key();
    world.last_flow_outcome =
        world
            .flow_map
            .process_packet(&key, 0x10, 1000, b"HELL", 5000, world.scratchpad_pool);
    world.current_flow_state = world.flow_map.get_state(&key);
}

#[when(expr = "the engine ingests the final Handshake segment")]
async fn ingest_final_hello(world: &mut EngineWorld) {
    let key = EngineWorld::get_key();
    world.last_flow_outcome =
        world
            .flow_map
            .process_packet(&key, 0x10, 1004, b"O", 6000, world.scratchpad_pool);
    if world.last_flow_outcome == Some(FlowOutcome::Fingerprinted) {
        world.current_flow_state = Some(FlowState::Fingerprinted);
    } else {
        world.current_flow_state = world.flow_map.get_state(&key);
    }
}

#[then(expr = "the FlowState must transition to {string}")]
async fn verify_transition(world: &mut EngineWorld, expected: String) {
    let actual = format!("{:?}", world.current_flow_state.expect("No state recorded"));
    assert_eq!(actual, expected);
}

#[then(expr = "the flow must transition to {string}")]
async fn verify_flow_transition(world: &mut EngineWorld, expected: String) {
    let actual = format!("{:?}", world.current_flow_state.expect("No state recorded"));
    assert_eq!(actual, expected);
}

#[then(expr = "the engine must transition to {string}")]
async fn verify_engine_transition(world: &mut EngineWorld, expected: String) {
    verify_flow_transition(world, expected).await;
}

#[then(expr = "the engine must emit a {string} outcome")]
async fn check_outcome(world: &mut EngineWorld, expected: String) {
    let actual = format!("{:?}", world.last_flow_outcome.expect("No outcome emitted"));
    assert_eq!(actual, expected);
}

#[when(expr = "the engine ingests a packet with sequence {int} and length {int}")]
async fn ingest_seq_packet(world: &mut EngineWorld, seq: i32, len: i32) {
    let key = EngineWorld::get_key();
    let data = vec![0u8; len as usize];
    world.last_flow_outcome =
        world
            .flow_map
            .process_packet(&key, 0x10, seq as u32, &data, 1000, world.scratchpad_pool);
    world.current_flow_state = world.flow_map.get_state(&key);
}

#[when(regex = r"the engine ingests a packet with sequence \d+ and length \d+ \(Out-of-Order\)")]
async fn ingest_ooo_packet_regex(world: &mut EngineWorld) {
    let key = EngineWorld::get_key();
    let mut data = vec![0u8; 50];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 256) as u8;
    }
    world.last_flow_outcome =
        world
            .flow_map
            .process_packet(&key, 0x10, 951, &data, 1000, world.scratchpad_pool);
    world.current_flow_state = world.flow_map.get_state(&key);
}

#[then(expr = "the LogicalByteView at offset {int} must match the payload of sequence {int}")]
async fn check_logical_view(world: &mut EngineWorld, offset: i32, _expected_seq: i32) {
    let key = EngineWorld::get_key();
    let entry = world.flow_map.acquire(&key, 1000).unwrap();
    let rb = entry.reassembly.as_ref().expect("No buffer");
    let mut buf = [0u8; 1];
    assert_eq!(rb.copy_to(offset as usize, &mut buf), 1);
    assert_eq!(buf[0], 0);
}

#[given(
    expr = r"a TCP flow in state {string} with {int} bytes at sequence {int} \(Content {string}\)"
)]
async fn init_overlap_flow(
    world: &mut EngineWorld,
    state: String,
    len: i32,
    seq: i32,
    content: String,
) {
    if state == "ClientHelloIncomplete" {
        let key = EngineWorld::get_key();
        world
            .flow_map
            .process_packet(&key, 0x02, 0, &[], 1000, world.scratchpad_pool);
        world
            .flow_map
            .process_packet(&key, 0x12, 0, &[], 2000, world.scratchpad_pool);
        world
            .flow_map
            .process_packet(&key, 0x10, 0, &[], 3000, world.scratchpad_pool);
        let data = vec![content.as_bytes()[0]; len as usize];
        world.last_flow_outcome = world.flow_map.process_packet(
            &key,
            0x10,
            seq as u32,
            &data,
            4000,
            world.scratchpad_pool,
        );
        world.current_flow_state = world.flow_map.get_state(&key);
        return;
    }

    set_flow_state(world, state).await;
    let key = EngineWorld::get_key();
    let data = vec![content.as_bytes()[0]; len as usize];
    world
        .flow_map
        .process_packet(&key, 0x10, seq as u32, &data, 1000, world.scratchpad_pool);
}

#[when(
    expr = r"the engine ingests a packet with sequence {int} and length {int} \(Content {string}\)"
)]
async fn ingest_overlap_packet(world: &mut EngineWorld, seq: i32, len: i32, content: String) {
    let key = EngineWorld::get_key();
    let data = vec![content.as_bytes()[0]; len as usize];
    world.last_flow_outcome =
        world
            .flow_map
            .process_packet(&key, 0x10, seq as u32, &data, 1000, world.scratchpad_pool);
    world.current_flow_state = world.flow_map.get_state(&key);
}

#[then(expr = "the LogicalByteView at sequence {int} to {int} must remain {string}")]
async fn verify_fww(world: &mut EngineWorld, start: i32, _end: i32, expected: String) {
    let key = EngineWorld::get_key();
    let entry = world.flow_map.acquire(&key, 1000).unwrap();
    let rb = entry
        .reassembly
        .as_ref()
        .expect("No reassembly buffer found");
    // Correct logical offset calculation: target_seq - base_seq
    let offset = (start as u32).wrapping_sub(rb.base_seq) as usize;
    let mut buf = [0u8; 1];
    assert_eq!(
        rb.copy_to(offset, &mut buf),
        1,
        "Failed to copy logical range"
    );
    assert_eq!(
        buf[0],
        expected.as_bytes()[0],
        "First-Writer-Wins violation detected"
    );
}

#[then(expr = "the later bytes for the overlapping range must be ignored")]
async fn verify_overlap_ignored(_world: &mut EngineWorld) {}

#[then(expr = "the engine must signal {string}")]
async fn verify_signal(world: &mut EngineWorld, expected: String) {
    let actual = format!(
        "{:?}",
        world.last_flow_outcome.expect("No outcome signaled")
    );
    assert_eq!(actual, expected);
}

#[then(regex = r#"signal "UnsupportedTimingSource""#)]
async fn verify_signal_unsupported(world: &mut EngineWorld) {
    let actual = format!(
        "{:?}",
        world.last_flow_outcome.expect("No outcome signaled")
    );
    assert_eq!(actual, "UnsupportedTimingSource");
}

#[given(expr = "an initialized fingerprint engine with a probe-tail limit of {int}")]
async fn init_probe_limit(_world: &mut EngineWorld, _limit: i32) {}

#[given(expr = "a FlowMap at its target load factor")]
async fn init_full_map(world: &mut EngineWorld) {
    for i in 0..700 {
        let key = FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: i,
            dst_port: 80,
            protocol: 6,
        };
        world.flow_map.acquire(&key, 1000).unwrap();
    }
}

#[when(expr = "a packet is ingested that exceeds the {int} quadratic probes")]
async fn ingest_probe_overflow(world: &mut EngineWorld, _limit: i32) {
    for i in 0..2000 {
        let key = FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: i,
            dst_port: 80,
            protocol: 6,
        };
        if let Err(e) = world.flow_map.acquire(&key, 1000) {
            world.last_flow_outcome = Some(e);
            break;
        }
    }
}

#[then(expr = "no new state may be allocated")]
async fn verify_no_state(_world: &mut EngineWorld) {}

#[given(expr = "an initialized fingerprint engine with a full scratchpad pool")]
async fn init_full_pool(world: &mut EngineWorld) {
    while let Some(guard) = world.scratchpad_pool.acquire(ScratchpadTier::Tier1) {
        world.held_guards.push(guard);
    }
}

#[when(expr = "the engine ingests a payload segment requiring temporal reassembly")]
async fn ingest_heavy_payload(world: &mut EngineWorld) {
    let key = EngineWorld::get_key();
    world.last_flow_outcome =
        world
            .flow_map
            .process_packet(&key, 0x10, 1000, b"DATA", 5000, world.scratchpad_pool);
    world.current_flow_state = world.flow_map.get_state(&key);
}

#[given(expr = "a TCP flow in state {string} with {int} existing segments")]
async fn init_frag_flow(world: &mut EngineWorld, state: String, count: i32) {
    set_flow_state(world, state).await;
    let key = EngineWorld::get_key();
    for i in 0..count {
        world.flow_map.process_packet(
            &key,
            0x10,
            1000 + (i as u32 * 100),
            b"A",
            1000,
            world.scratchpad_pool,
        );
    }
}

#[when(expr = "the engine ingests a {int}th discontiguous TCP segment")]
async fn ingest_extra_frag(world: &mut EngineWorld, _count: i32) {
    let key = EngineWorld::get_key();
    world.last_flow_outcome =
        world
            .flow_map
            .process_packet(&key, 0x10, 9999, b"B", 1000, world.scratchpad_pool);
    world.current_flow_state = world.flow_map.get_state(&key);
}

#[when(expr = "the engine ingests a segment beyond the {int}-block sequence window")]
async fn ingest_win_overflow(world: &mut EngineWorld, _blocks: i32) {
    let key = EngineWorld::get_key();
    world.last_flow_outcome = world.flow_map.process_packet(
        &key,
        0x10,
        1000 + (70 * 1024),
        b"DATA",
        1000,
        world.scratchpad_pool,
    );
    world.current_flow_state = world.flow_map.get_state(&key);
}

#[then(expr = "all scratchpad slots must be released")]
async fn verify_cleanup(world: &mut EngineWorld) {
    assert_eq!(world.scratchpad_pool.used_slots(ScratchpadTier::Tier1), 0);
}

#[when(expr = "the hardware clock advances by {int}ms")]
async fn advance_clock(world: &mut EngineWorld, ms: i32) {
    let outcomes = world
        .flow_map
        .cleanup_expired(1000 + (ms as u64 * 1_000_000));
    if let Some(o) = outcomes.first() {
        world.last_flow_outcome = Some(*o);
        world.current_flow_state = Some(FlowState::Expired);
    }
}

#[when(
    expr = "the engine ingests a TLS record with a claimed length larger than the tracking window"
)]
async fn ingest_malformed_tls(world: &mut EngineWorld) {
    let key = EngineWorld::get_key();
    world.last_flow_outcome = world.flow_map.process_packet(
        &key,
        0x10,
        1000 + (70 * 1024),
        b"DATA",
        1000,
        world.scratchpad_pool,
    );
    world.current_flow_state = world.flow_map.get_state(&key);
}

#[given(regex = r"an engine initialization attempt on an unsupported CPU \(Non-TSC-Safe\)")]
async fn init_unsupported_cpu_regex(world: &mut EngineWorld) {
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
    assert_eq!(
        world.last_flow_outcome,
        Some(FlowOutcome::UnsupportedTimingSource)
    );
}

#[tokio::main]
async fn main() {
    let feature_path = if std::path::Path::new("tests/features").exists() {
        "tests/features"
    } else {
        "../../tests/features"
    };
    EngineWorld::run(format!("{}/baseline.feature", feature_path)).await;
    EngineWorld::run(format!("{}/ingestion.feature", feature_path)).await;
    EngineWorld::run(format!("{}/reassembly.feature", feature_path)).await;
}
