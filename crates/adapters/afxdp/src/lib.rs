#[cfg(target_os = "linux")]
use flux_engine_core::PacketView;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU32, Ordering};
#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;
#[cfg(target_os = "linux")]
use libc::{mmap, munmap, PROT_READ, PROT_WRITE, MAP_SHARED, MAP_FAILED, bind, sockaddr_xdp, AF_XDP, close};
#[cfg(target_os = "linux")]
use libbpf_sys::{xdp_desc, xdp_ring_offset, xdp_umem_reg, SOL_XDP, XDP_UMEM_REG};

/// Represents a raw AF_XDP ring (Fill, Completion, RX, or TX).
#[cfg(target_os = "linux")]
pub struct XskRing<T> {
    pub base_ptr: *mut libc::c_void,
    pub map_size: usize,
    pub producer: *mut AtomicU32,
    pub consumer: *mut AtomicU32,
    pub descriptors: *mut T,
    pub mask: u32,
    pub size: u32,
}

#[cfg(target_os = "linux")]
impl<T> XskRing<T> {
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
            base_ptr: ptr,
            map_size: size,
            producer: (ptr as usize + ring_offsets.producer as usize) as *mut AtomicU32,
            consumer: (ptr as usize + ring_offsets.consumer as usize) as *mut AtomicU32,
            descriptors: (ptr as usize + ring_offsets.desc as usize) as *mut T,
            mask: (size / std::mem::size_of::<T>() - 1) as u32,
            size: (size / std::mem::size_of::<T>()) as u32,
        })
    }

    /// Advances the consumer pointer, releasing descriptors back to the kernel.
    #[inline(always)]
    pub fn release(&self, count: u32) {
        unsafe {
            let current = (*self.consumer).load(Ordering::Relaxed);
            (*self.consumer).store(current.wrapping_add(count), Ordering::Release);
        }
    }

    /// Pushes items into the ring.
    pub unsafe fn produce(&self, items: &[T]) -> usize {
        let prod = (*self.producer).load(Ordering::Relaxed);
        let cons = (*self.consumer).load(Ordering::Acquire);
        
        let free = self.size.wrapping_sub(prod.wrapping_sub(cons));
        let count = std::cmp::min(free as usize, items.len());
        
        for i in 0..count {
            let idx = (prod.wrapping_add(i as u32)) & self.mask;
            *self.descriptors.add(idx as usize) = std::ptr::read(&items[i]);
        }
        
        (*self.producer).store(prod.wrapping_add(count as u32), Ordering::Release);
        count
    }
}

#[cfg(target_os = "linux")]
impl<T> Drop for XskRing<T> {
    fn drop(&mut self) {
        unsafe { munmap(self.base_ptr, self.map_size); }
    }
}

#[cfg(target_os = "linux")]
pub struct AfXdpDriver {
    pub fd: RawFd,
    pub rx_ring: XskRing<xdp_desc>,
    pub fill_ring: XskRing<u64>,
    pub completion_ring: XskRing<u64>,
    pub umem_base: *mut u8,
    pub umem_size: usize,
    pub queue_id: u16,
}

#[cfg(target_os = "linux")]
impl AfXdpDriver {
    /// Hot-path ingestion.
    /// 
    /// Enforces MP-004 Mandate: Immediate Descriptor Release.
    /// Soundness: The 'a lifetime is tied to the driver self, ensuring
    /// packets cannot outlive the UMEM region.
    pub fn ingest<'a, F>(&'a self, max_packets: usize, mut f: F) -> usize 
    where F: FnMut(&AfXdpPacketView<'a>) 
    {
        unsafe {
            let prod = (*self.rx_ring.producer).load(Ordering::Acquire);
            let cons = (*self.rx_ring.consumer).load(Ordering::Relaxed);
            
            let available = prod.wrapping_sub(cons);
            let count = std::cmp::min(available as usize, max_packets);
            
            for i in 0..count {
                let idx = (cons.wrapping_add(i as u32)) & self.rx_ring.mask;
                let desc = &*self.rx_ring.descriptors.add(idx as usize);
                
                let data_ptr = self.umem_base.add(desc.addr as usize);
                let data = std::slice::from_raw_parts(data_ptr, desc.len as usize);
                
                let view = AfXdpPacketView {
                    data,
                    addr: desc.addr,
                    timestamp_ns: 0, 
                    queue_id: self.queue_id,
                };
                
                f(&view);
            }
            
            // MP-004: Immediate descriptor release after processing
            if count > 0 {
                self.rx_ring.release(count as u32);
            }
            
            count
        }
    }

    /// Recycles UMEM addresses back to the Fill Ring.
    pub unsafe fn replenish_fill(&self, addrs: &[u64]) -> usize {
        self.fill_ring.produce(addrs)
    }
}

#[cfg(target_os = "linux")]
impl Drop for AfXdpDriver {
    fn drop(&mut self) {
        unsafe {
            munmap(self.umem_base as *mut libc::c_void, self.umem_size);
            close(self.fd);
        }
    }
}

#[cfg(target_os = "linux")]
pub struct AfXdpPacketView<'a> {
    pub data: &'a [u8],
    pub addr: u64,
    pub timestamp_ns: u64,
    pub queue_id: u16,
}

#[cfg(target_os = "linux")]
impl<'a> PacketView for AfXdpPacketView<'a> {
    fn timestamp_ns(&self) -> u64 { self.timestamp_ns }
    fn data(&self) -> &[u8] { self.data }
    fn ingress_ifindex(&self) -> Option<u32> { None } 
    fn rss_queue_id(&self) -> Option<u16> { Some(self.queue_id) }
}
