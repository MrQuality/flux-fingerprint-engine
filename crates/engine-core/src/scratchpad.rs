use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Tier dimensions
pub const TIER1_SLOT_SIZE: usize = 16 * 1024; // 16 KiB
pub const TIER1_SLOTS: usize = 2048;
pub const TIER2_SLOT_SIZE: usize = 64 * 1024; // 64 KiB
pub const TIER2_SLOTS: usize = 512;

/// A tiered, wait-free pool of forensic scratchpads for temporal reassembly.
pub struct ForensicScratchpadPool {
    tier1_masks: [AtomicU64; 32], 
    tier2_masks: [AtomicU64; 8],  
    
    // Backing storage
    tier1_storage: Vec<u8>,
    tier2_storage: Vec<u8>,

    // ADR-001: Mandatory Exhaustion Telemetry
    pub scratchpad_exhaustion_total: AtomicUsize,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ScratchpadTier {
    Tier1, 
    Tier2, 
}

impl ForensicScratchpadPool {
    pub fn new() -> Self {
        Self {
            tier1_masks: Default::default(),
            tier2_masks: Default::default(),
            tier1_storage: vec![0u8; TIER1_SLOTS * TIER1_SLOT_SIZE],
            tier2_storage: vec![0u8; TIER2_SLOTS * TIER2_SLOT_SIZE],
            scratchpad_exhaustion_total: AtomicUsize::new(0),
        }
    }

    /// Acquires a scratchpad slot and returns its slice.
    pub fn acquire(&self, tier: ScratchpadTier) -> Option<(usize, &mut [u8])> {
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
                    Ok(_) => {
                        let slot_idx = i * 64 + bit as usize;
                        let slice = self.get_mut_slice(tier, slot_idx);
                        return Some((slot_idx, slice));
                    }
                    Err(actual) => current = actual,
                }
            }
        }
        
        // ADR-001: Signal exhaustion
        self.scratchpad_exhaustion_total.fetch_add(1, Ordering::Relaxed);
        None
    }

    fn get_mut_slice(&self, tier: ScratchpadTier, idx: usize) -> &mut [u8] {
        unsafe {
            match tier {
                ScratchpadTier::Tier1 => {
                    let ptr = self.tier1_storage.as_ptr() as *mut u8;
                    std::slice::from_raw_parts_mut(ptr.add(idx * TIER1_SLOT_SIZE), TIER1_SLOT_SIZE)
                }
                ScratchpadTier::Tier2 => {
                    let ptr = self.tier2_storage.as_ptr() as *mut u8;
                    std::slice::from_raw_parts_mut(ptr.add(idx * TIER2_SLOT_SIZE), TIER2_SLOT_SIZE)
                }
            }
        }
    }

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
    fn test_scratchpad_storage_access() {
        let pool = ForensicScratchpadPool::new();
        let (idx, slice) = pool.acquire(ScratchpadTier::Tier1).unwrap();
        slice[0] = 42;
        assert_eq!(pool.tier1_storage[idx * TIER1_SLOT_SIZE], 42);
        pool.release(ScratchpadTier::Tier1, idx);
    }

    #[test]
    fn test_scratchpad_exhaustion_telemetry() {
        let pool = ForensicScratchpadPool::new();
        for _ in 0..TIER2_SLOTS {
            pool.acquire(ScratchpadTier::Tier2).unwrap();
        }
        assert_eq!(pool.scratchpad_exhaustion_total.load(Ordering::Relaxed), 0);
        assert!(pool.acquire(ScratchpadTier::Tier2).is_none());
        assert_eq!(pool.scratchpad_exhaustion_total.load(Ordering::Relaxed), 1);
    }
}
