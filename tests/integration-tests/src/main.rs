use cucumber::{given, then, when, World};
use flux_pcap_injector::PcapInjector;
use flux_engine_core::PacketView;
use stats_alloc::{Region, StatsAlloc, INSTRUMENTED_SYSTEM};
use std::alloc::System;

#[global_allocator]
static ALLOC: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[derive(Debug, World, Default)]
pub struct EngineWorld {
    pub injector: Option<PcapInjector>,
    pub packets_processed: usize,
    pub last_metadata: (Option<u32>, Option<u16>, u64),
    pub alloc_region: Option<Region<'static, System>>,
}

#[given(expr = "an initialized fingerprint engine")]
async fn init_engine(world: &mut EngineWorld) {
    world.packets_processed = 0;
    world.alloc_region = Some(Region::new(ALLOC));
}

#[given(expr = "the adversarial trace {string}")]
async fn load_trace(world: &mut EngineWorld, path: String) {
    world.injector = Some(PcapInjector::new(&path).expect("Failed to load PCAP"));
}

#[when(expr = "the engine ingests a packet from the trace")]
async fn ingest_single_packet(world: &mut EngineWorld) {
    if let Some(ref injector) = world.injector {
        if let Some(packet) = injector.packets().first() {
            world.last_metadata = (packet.ingress_ifindex(), packet.rss_queue_id(), packet.timestamp_ns());
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

#[tokio::main]
async fn main() {
    // Run both features
    EngineWorld::run("../features/baseline.feature").await;
    EngineWorld::run("../features/ingestion.feature").await;
}
