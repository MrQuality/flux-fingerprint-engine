#[cfg(target_os = "linux")]
use flux_engine_core::PacketView;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU32, Ordering};
#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;
#[cfg(target_os = "linux")]
use libc::{mmap, PROT_READ, PROT_WRITE, MAP_SHARED, MAP_FAILED};

#[cfg(target_os = "linux")]
pub const XDP_PGOFF_RX_RING: i64 = 0x00000000;
#[cfg(target_os = "linux")]
pub const XDP_PGOFF_TX_RING: i64 = 0x80000000;
#[cfg(target_os = "linux")]
pub const XDP_PGOFF_FILL_RING: i64 = 0x100000000;
#[cfg(target_os = "linux")]
pub const XDP_PGOFF_COMPLETION_RING: i64 = 0x180000000;

#[cfg(target_os = "linux")]
pub struct XskRing {
    pub producer: *mut AtomicU32,
    pub consumer: *mut AtomicU32,
    pub descriptors: *mut u8,
    pub mask: u32,
    pub size: u32,
}

#[cfg(target_os = "linux")]
impl XskRing {
    pub unsafe fn map(fd: RawFd, offset: i64, size: usize) -> anyhow::Result<Self> {
        let ptr = mmap(
            std::ptr::null_mut(),
            size,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd,
            offset,
        );
        
        if ptr == MAP_FAILED {
            return Err(anyhow::anyhow!("Failed to mmap AF_XDP ring"));
        }
        
        Ok(Self {
            producer: ptr as *mut AtomicU32,
            consumer: (ptr as usize + 64) as *mut AtomicU32,
            descriptors: (ptr as usize + 128) as *mut u8,
            mask: (size / 8 - 1) as u32,
            size: size as u32,
        })
    }

    #[inline(always)]
    pub fn release(&self, count: u32) {
        unsafe {
            let current = (*self.consumer).load(Ordering::Relaxed);
            (*self.consumer).store(current.wrapping_add(count), Ordering::Release);
        }
    }
}

#[cfg(target_os = "linux")]
pub struct AfXdpDriver {
    pub rx_ring: XskRing,
    pub fill_ring: XskRing,
    pub umem_base: *mut u8,
}

#[cfg(target_os = "linux")]
impl AfXdpDriver {
    pub fn rx_burst<'a>(&self, out: &mut [AfXdpPacketView<'a>]) -> usize {
        unsafe {
            let prod = (*self.rx_ring.producer).load(Ordering::Acquire);
            let cons = (*self.rx_ring.consumer).load(Ordering::Relaxed);
            
            let available = prod.wrapping_sub(cons);
            let count = std::cmp::min(available as usize, out.len());
            
            for i in 0..count {
                let _idx = (cons.wrapping_add(i as u32)) & self.rx_ring.mask;
                out[i] = AfXdpPacketView::default();
            }
            
            count
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Default)]
pub struct AfXdpPacketView<'a> {
    pub data: &'a [u8],
    pub addr: u64,
    pub len: u32,
    pub timestamp_ns: u64,
}

#[cfg(target_os = "linux")]
impl<'a> PacketView for AfXdpPacketView<'a> {
    fn timestamp_ns(&self) -> u64 { self.timestamp_ns }
    fn data(&self) -> &[u8] { self.data }
}
