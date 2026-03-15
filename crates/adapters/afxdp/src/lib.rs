#[cfg(target_os = "linux")]
use flux_engine_core::PacketView;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU32, Ordering};
#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;
#[cfg(target_os = "linux")]
use libc::{mmap, PROT_READ, PROT_WRITE, MAP_SHARED, MAP_FAILED, setsockopt, SOL_XDP, bind, sockaddr_xdp, AF_XDP};

#[cfg(target_os = "linux")]
pub const XDP_UMEM_REG: i32 = 3;
#[cfg(target_os = "linux")]
pub const XDP_RX_RING: i32 = 1;
#[cfg(target_os = "linux")]
pub const XDP_TX_RING: i32 = 2;
#[cfg(target_os = "linux")]
pub const XDP_UMEM_FILL_RING: i32 = 5;
#[cfg(target_os = "linux")]
pub const XDP_UMEM_COMPLETION_RING: i32 = 6;

#[cfg(target_os = "linux")]
#[repr(C)]
pub struct xdp_umem_reg {
    pub addr: u64,
    pub len: u64,
    pub chunk_size: u32,
    pub headroom: u32,
    pub flags: u32,
}

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

    pub unsafe fn produce_fill(&self, addrs: &[u64]) -> usize {
        let prod = (*self.producer).load(Ordering::Relaxed);
        let cons = (*self.consumer).load(Ordering::Acquire);
        
        let free = self.size.wrapping_sub(prod.wrapping_sub(cons));
        let count = std::cmp::min(free as usize, addrs.len());
        
        for i in 0..count {
            let idx = (prod.wrapping_add(i as u32)) & self.mask;
            let desc_ptr = self.descriptors as *mut u64;
            *desc_ptr.add(idx as usize) = addrs[i];
        }
        
        (*self.producer).store(prod.wrapping_add(count as u32), Ordering::Release);
        count
    }
}

#[cfg(target_os = "linux")]
pub struct AfXdpDriver {
    pub fd: RawFd,
    pub rx_ring: XskRing,
    pub fill_ring: XskRing,
    pub umem_base: *mut u8,
}

#[cfg(target_os = "linux")]
impl AfXdpDriver {
    pub unsafe fn register_umem(fd: RawFd, addr: *mut u8, len: u64) -> anyhow::Result<()> {
        let reg = xdp_umem_reg {
            addr: addr as u64,
            len,
            chunk_size: 4096,
            headroom: 0,
            flags: 0,
        };
        
        if setsockopt(fd, SOL_XDP, XDP_UMEM_REG, &reg as *const _ as *const libc::c_void, std::mem::size_of::<xdp_umem_reg>() as u32) != 0 {
            return Err(anyhow::anyhow!("Failed to register AF_XDP UMEM"));
        }
        
        Ok(())
    }

    pub unsafe fn bind_socket(fd: RawFd, ifindex: u32, queue_id: u32) -> anyhow::Result<()> {
        let mut sxdp: sockaddr_xdp = std::mem::zeroed();
        sxdp.sxdp_family = AF_XDP as u16;
        sxdp.sxdp_ifindex = ifindex;
        sxdp.sxdp_queue_id = queue_id;
        sxdp.sxdp_flags = 0; // Default to XDP_COPY if zero-copy is not requested/available
        
        if bind(fd, &sxdp as *const _ as *const libc::sockaddr, std::mem::size_of::<sockaddr_xdp>() as u32) != 0 {
            return Err(anyhow::anyhow!("Failed to bind AF_XDP socket"));
        }
        
        Ok(())
    }

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
                    timestamp_ns: 0,
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
