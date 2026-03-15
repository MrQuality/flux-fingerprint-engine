use std::sync::atomic::{AtomicU64, Ordering};

/// A tiered, wait-free pool of forensic scratchpads for temporal reassembly.
/// 
/// CA-005: 2-Tiered Allocation
/// - Tier 1: 2048 x 16KB slots (Standard handshakes)
/// - Tier 2: 512 x 64KB slots (Extended handshakes)
pub struct ForensicScratchpadPool {
    tier1_masks: [AtomicU64; 32], // 32 * 64 = 2048 bits
    tier2_masks: [AtomicU64; 8],  // 8 * 64 = 512 bits
}

#[derive(Debug, PartialEq)]
pub enum ScratchpadTier {
    Tier1, // 16KB
    Tier2, // 64KB
}

impl ForensicScratchpadPool {
    pub fn new() -> Self {
        Self {
            tier1_masks: Default::default(),
            tier2_masks: Default::default(),
        }
    }

    /// Acquires a scratchpad slot using wait-free bitmask logic (CA-009).
    pub fn acquire(&self, tier: ScratchpadTier) -> Option<usize> {
        let masks: &[AtomicU64] = match tier {
            ScratchpadTier::Tier1 => &self.tier1_masks,
            ScratchpadTier::Tier2 => &self.tier2_masks,
        };

        for (i, mask) in masks.iter().enumerate() {
            let mut current = mask.load(Ordering::Relaxed);
            while current != !0 {
                let bit = (!current).trailing_zeros();
                if bit >= 64 { break; } 
                let next = current | (1 << bit);
                match mask.compare_exchange_weak(current, next, Ordering::Acquire, Ordering::Relaxed) {
                    Ok(_) => return Some(i * 64 + bit as usize),
                    Err(actual) => current = actual,
                }
            }
        }
        None
    }

    /// Releases a scratchpad slot back to the pool.
    pub fn release(&self, tier: ScratchpadTier, slot_idx: usize) {
        let masks: &[AtomicU64] = match tier {
            ScratchpadTier::Tier1 => &self.tier1_masks,
            ScratchpadTier::Tier2 => &self.tier2_masks,
        };

        let i = slot_idx / 64;
        let bit = (slot_idx % 64) as u32;
        masks[i].fetch_and(!(1 << bit), Ordering::Release);
    }
}

#[cfg(test)]
mod pool_tests {
    use super::*;

    #[test]
    fn test_scratchpad_allocation_exhaustion() {
        let pool = ForensicScratchpadPool::new();
        
        // Fill Tier 2 (512 slots)
        for _ in 0..512 {
            assert!(pool.acquire(ScratchpadTier::Tier2).is_some());
        }
        // Next should fail
        assert!(pool.acquire(ScratchpadTier::Tier2).is_none());
        
        // Release one and re-acquire
        pool.release(ScratchpadTier::Tier2, 10);
        assert_eq!(pool.acquire(ScratchpadTier::Tier2), Some(10));
    }
}
