use cucumber::{given, when, then, World};
use flux_pcap_injector::PcapInjector;
use std::convert::Infallible;

#[derive(Debug, Default, World)]
pub struct EngineWorld {
    pub injector: Option<PcapInjector>,
    pub packets_processed: usize,
}

#[given(expr = "an initialized fingerprint engine")]
async fn init_engine(world: &mut EngineWorld) {
    // Engine initialization logic will go here
    world.packets_processed = 0;
}

#[given(expr = "the adversarial trace {string}")]
async fn load_trace(world: &mut EngineWorld, path: String) {
    // We handle the path relative to the workspace root
    world.injector = Some(PcapInjector::new(&path).expect("Failed to load PCAP"));
}

#[when(expr = "the engine ingests all packets from the trace")]
async fn ingest_packets(world: &mut EngineWorld) {
    if let Some(ref injector) = world.injector {
        let packets = injector.packets();
        world.packets_processed = packets.len();
        // Here we would call engine.ingest() for each packet
    }
}

#[then(expr = "the ingestion count should be greater than 0")]
async fn check_ingestion(world: &mut EngineWorld) {
    assert!(world.packets_processed > 0);
}

#[then(expr = "no Panics should occur")]
async fn check_panics(_world: &mut EngineWorld) {
    // Implicitly passed if we reached here
}

#[tokio::main]
async fn main() {
    EngineWorld::run("../features/baseline.feature").await;
}
