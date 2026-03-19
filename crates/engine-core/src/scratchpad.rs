use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Tier dimensions
pub const TIER1_SLOT_SIZE: usize = 16 * 1024; // 16 KiB
pub const TIER1_SLOTS: usize = 2048;
pub const TIER2_SLOT_SIZE: usize = 64 * 1024; // 64 KiB
pub const TIER2_SLOTS: usize = 512;

/// A tiered, lock-free pool of forensic scratchpads for temporal reassembly.
pub struct ForensicScratchpadPool {
    tier1_masks: [AtomicU64; 32],
    tier2_masks: [AtomicU64; 8],

    tier1_storage: Vec<u8>,
    tier2_storage: Vec<u8>,

    /// ADR-001: Mandatory Exhaustion Telemetry
    pub scratchpad_exhaustion_total: AtomicUsize,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ScratchpadTier {
    Tier1,
    Tier2,
}

/// RAII Guard for a scratchpad slot.
pub struct ScratchpadGuard<'a> {
    pool: &'a ForensicScratchpadPool,
    tier: ScratchpadTier,
    slot_idx: usize,
    data: *mut [u8],
}

impl<'a> std::fmt::Debug for ScratchpadGuard<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScratchpadGuard")
            .field("tier", &self.tier)
            .field("slot_idx", &self.slot_idx)
            .finish()
    }
}

impl<'a> Deref for ScratchpadGuard<'a> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.data }
    }
}

impl<'a> DerefMut for ScratchpadGuard<'a> {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { &mut *self.data }
    }
}

impl<'a> Drop for ScratchpadGuard<'a> {
    fn drop(&mut self) {
        self.pool.release(self.tier, self.slot_idx);
    }
}

impl Default for ForensicScratchpadPool {
    fn default() -> Self {
        Self::new()
    }
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

    /// Acquires a scratchpad slot and returns a Guard tied to the pool's lifetime.
    pub fn acquire(&self, tier: ScratchpadTier) -> Option<ScratchpadGuard<'_>> {
        let masks: &[AtomicU64] = match tier {
            ScratchpadTier::Tier1 => &self.tier1_masks,
            ScratchpadTier::Tier2 => &self.tier2_masks,
        };

        for (i, mask) in masks.iter().enumerate() {
            let mut current = mask.load(Ordering::Relaxed);
            while current != !0 {
                let bit = (!current).trailing_zeros();
                if bit >= 64 {
                    break;
                }
                let next = current | (1 << bit);
                match mask.compare_exchange_weak(
                    current,
                    next,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        let slot_idx = i * 64 + bit as usize;
                        let data = self.get_mut_ptr(tier, slot_idx);
                        return Some(ScratchpadGuard {
                            pool: self,
                            tier,
                            slot_idx,
                            data,
                        });
                    }
                    Err(actual) => current = actual,
                }
            }
        }
        self.scratchpad_exhaustion_total
            .fetch_add(1, Ordering::Relaxed);
        None
    }

    pub fn used_slots(&self, tier: ScratchpadTier) -> usize {
        let masks: &[AtomicU64] = match tier {
            ScratchpadTier::Tier1 => &self.tier1_masks,
            ScratchpadTier::Tier2 => &self.tier2_masks,
        };

        masks
            .iter()
            .map(|mask| mask.load(Ordering::Acquire).count_ones() as usize)
            .sum()
    }

    fn get_mut_ptr(&self, tier: ScratchpadTier, idx: usize) -> *mut [u8] {
        unsafe {
            let (base, size) = match tier {
                ScratchpadTier::Tier1 => (self.tier1_storage.as_ptr(), TIER1_SLOT_SIZE),
                ScratchpadTier::Tier2 => (self.tier2_storage.as_ptr(), TIER2_SLOT_SIZE),
            };
            let ptr = base.add(idx * size) as *mut u8;
            std::ptr::slice_from_raw_parts_mut(ptr, size)
        }
    }

    fn release(&self, tier: ScratchpadTier, slot_idx: usize) {
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
    fn test_raii_release() {
        let pool = ForensicScratchpadPool::new();
        {
            let mut guard = pool
                .acquire(ScratchpadTier::Tier1)
                .expect("Acquisition failed");
            guard[0] = 100;
        }
        assert!(pool.acquire(ScratchpadTier::Tier1).is_some());
    }
}
