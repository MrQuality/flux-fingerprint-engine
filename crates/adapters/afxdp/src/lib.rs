#[cfg(target_os = "linux")]
use flux_engine_core::PacketView;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU32, Ordering};
#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;
#[cfg(target_os = "linux")]
use libc::{mmap, PROT_READ, PROT_WRITE, MAP_SHARED, MAP_FAILED};

#[cfg(target_os = "linux")]
#[repr(C)]
pub struct xdp_desc {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
pub struct xdp_ring_offset {
    pub producer: u64,
    pub consumer: u64,
    pub desc: u64,
    pub flags: u64,
}

#[cfg(target_os = "linux")]
pub struct XskRing {
    pub producer: *mut AtomicU32,
    pub consumer: *mut AtomicU32,
    pub descriptors: *mut xdp_desc,
    pub mask: u32,
    pub size: u32,
}

#[cfg(target_os = "linux")]
impl XskRing {
    /// Maps a raw AF_XDP ring from the kernel using explicit layout offsets.
    pub unsafe fn map(fd: RawFd, mmap_offset: i64, size: usize, ring_offsets: &xdp_ring_offset) -> anyhow::Result<Self> {
        let ptr = mmap(
            std::ptr::null_mut(),
            size,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd,
            mmap_offset,
        );
        
        if ptr == MAP_FAILED {
            return Err(anyhow::anyhow!("Failed to mmap AF_XDP ring"));
        }
        
        Ok(Self {
            producer: (ptr as usize + ring_offsets.producer as usize) as *mut AtomicU32,
            consumer: (ptr as usize + ring_offsets.consumer as usize) as *mut AtomicU32,
            descriptors: (ptr as usize + ring_offsets.desc as usize) as *mut xdp_desc,
            mask: (size / std::mem::size_of::<xdp_desc>() - 1) as u32,
            size: (size / std::mem::size_of::<xdp_desc>()) as u32,
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
                let idx = (cons.wrapping_add(i as u32)) & self.rx_ring.mask;
                let desc = &*self.rx_ring.descriptors.add(idx as usize);
                
                let data_ptr = self.umem_base.add(desc.addr as usize);
                let data = std::slice::from_raw_parts(data_ptr, desc.len as usize);
                
                out[i] = AfXdpPacketView {
                    data,
                    addr: desc.addr,
                    len: desc.len,
                    timestamp_ns: 0, // In practice, extracted from XDP metadata if supported
                };
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
