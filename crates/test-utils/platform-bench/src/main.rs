use anyhow::Result;
use rand::distributions::{Distribution, WeightedIndex};
use rand::thread_rng;

#[cfg(target_os = "linux")]
use perf_event::events::Hardware;
#[cfg(target_os = "linux")]
use perf_event::{Builder, Group};

/// IMIX Distribution (7:4:1 ratio for 64B, 570B, 1514B packets)
struct ImixGenerator {
    sizes: [usize; 3],
    weights: WeightedIndex<u32>,
}

impl ImixGenerator {
    fn new() -> Self {
        Self {
            sizes: [64, 570, 1514],
            weights: WeightedIndex::new([7, 4, 1]).unwrap(),
        }
    }

    fn next_packet_size(&self) -> usize {
        let mut rng = thread_rng();
        self.sizes[self.weights.sample(&mut rng)]
    }
}

fn main() -> Result<()> {
    println!("FluxFingerprint Platform Verification Benchmark (CA-01)");
    let gen = ImixGenerator::new();

    let iterations = 1_000_000;

    #[cfg(target_os = "linux")]
    {
        let mut group = Group::new()?;
        let cycles = Builder::new()
            .group(&mut group)
            .kind(Hardware::CPU_CYCLES)
            .build()?;
        let instructions = Builder::new()
            .group(&mut group)
            .kind(Hardware::INSTRUCTIONS)
            .build()?;
        let cache_misses = Builder::new()
            .group(&mut group)
            .kind(Hardware::CACHE_MISSES)
            .build()?;

        println!("Starting benchmark ({} iterations)...", iterations);
        group.enable()?;

        for _ in 0..iterations {
            let _size = gen.next_packet_size();
            // Simulate baseline processing
            std::hint::black_box(_size);
        }

        group.disable()?;
        let counts = group.read()?;

        let inst = counts[&instructions];
        let cyc = counts[&cycles];
        let miss = counts[&cache_misses];

        println!("Benchmark Results:");
        println!("- CPU Cycles: {}", cyc);
        println!("- Instructions: {}", inst);
        println!("- IPC: {:.2}", inst as f64 / cyc as f64);
        println!("- Cache Misses: {}", miss);
        println!("- Avg Cycles/Packet: {:.2}", cyc as f64 / iterations as f64);
    }

    #[cfg(not(target_os = "linux"))]
    {
        println!("Starting simulation ({} iterations)...", iterations);
        for _ in 0..iterations {
            let _size = gen.next_packet_size();
            std::hint::black_box(_size);
        }
        println!("Simulation complete. Performance counters require Linux.");
    }

    Ok(())
}
