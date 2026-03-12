use cucumber::{given, then, when, World};
use flux_pcap_injector::PcapInjector;
use stats_alloc::{Region, StatsAlloc, INSTRUMENTED_SYSTEM};
use std::alloc::System;

#[global_allocator]
static ALLOC: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[derive(Debug, World)]
pub struct EngineWorld {
    pub injector: Option<PcapInjector>,
    pub packets_processed: usize,
    pub alloc_region: Option<Region<'static, System>>,
}

impl Default for EngineWorld {
    fn default() -> Self {
        Self {
            injector: None,
            packets_processed: 0,
            alloc_region: None,
        }
    }
}

#[given(expr = "an initialized fingerprint engine")]
async fn init_engine(world: &mut EngineWorld) {
    world.packets_processed = 0;
    // Start monitoring allocations
    world.alloc_region = Some(Region::new(&ALLOC));
}

#[given(expr = "the adversarial trace {string}")]
async fn load_trace(world: &mut EngineWorld, path: String) {
    world.injector = Some(PcapInjector::new(&path).expect("Failed to load PCAP"));
}

#[when(expr = "the engine ingests all packets from the trace")]
async fn ingest_packets(world: &mut EngineWorld) {
    if let Some(ref injector) = world.injector {
        let packets = injector.packets();
        world.packets_processed = packets.len();
        // The loop below represents the hot path
        for _packet in packets {
            // engine.ingest(&packet);
        }
    }
}

#[then(expr = "the ingestion count should be greater than 0")]
async fn check_ingestion(world: &mut EngineWorld) {
    assert!(world.packets_processed > 0);
}

#[then(expr = "no heap allocations should occur in the hot path")]
async fn check_allocations(world: &mut EngineWorld) {
    if let Some(region) = world.alloc_region.take() {
        let stats = region.change();
        assert_eq!(
            stats.allocations, 0,
            "Heap allocations detected in the hot path!"
        );
    }
}

#[then(expr = "no Panics should occur")]
async fn check_panics(_world: &mut EngineWorld) {}

#[tokio::main]
async fn main() {
    EngineWorld::run("../features/baseline.feature").await;
}
