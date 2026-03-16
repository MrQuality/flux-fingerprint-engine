use flux_engine_core::PacketView;
#[cfg(target_os = "linux")]
use std::slice;
#[cfg(target_os = "linux")]
use dpdk_sys::{rte_mbuf, rte_pktmbuf_free, rte_eth_rx_burst};

#[cfg(target_os = "linux")]
pub struct DpdkMbufView {
    pub mbuf_ptr: *mut rte_mbuf,
    pub timestamp_ns: u64,
}

#[cfg(target_os = "linux")]
impl PacketView for DpdkMbufView {
    fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }

    fn data(&self) -> &[u8] {
        unsafe {
            if self.mbuf_ptr.is_null() {
                return &[];
            }
            let mbuf = &*self.mbuf_ptr;
            let data_ptr = (mbuf.buf_addr as *mut u8).add(mbuf.data_off as usize);
            slice::from_raw_parts(data_ptr, mbuf.data_len as usize)
        }
    }

    fn ingress_ifindex(&self) -> Option<u32> {
        unsafe {
            if self.mbuf_ptr.is_null() { return None; }
            Some((*self.mbuf_ptr).port as u32)
        }
    }

    fn rss_queue_id(&self) -> Option<u16> {
        unsafe {
            if self.mbuf_ptr.is_null() { return None; }
            let rss_hash = (*self.mbuf_ptr).hash.rss;
            Some((rss_hash % 65536) as u16)
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for DpdkMbufView {
    fn drop(&mut self) {
        if !self.mbuf_ptr.is_null() {
            unsafe {
                rte_pktmbuf_free(self.mbuf_ptr);
            }
        }
    }
}

pub struct DpdkDriver {
    pub port_id: u16,
}

impl DpdkDriver {
    pub fn new(port_id: u16) -> Self {
        Self { port_id }
    }

    #[cfg(target_os = "linux")]
    pub fn rx_burst<'a>(&self, out: &mut [DpdkMbufView]) -> usize {
        let mut mbuf_ptrs: [*mut rte_mbuf; 32] = [std::ptr::null_mut(); 32];
        let to_read = std::cmp::min(out.len(), 32) as u16;
        
        let nb_rx = unsafe { 
            rte_eth_rx_burst(self.port_id, 0, mbuf_ptrs.as_mut_ptr(), to_read) 
        };
        
        for i in 0..nb_rx as usize {
            out[i] = DpdkMbufView { 
                mbuf_ptr: mbuf_ptrs[i], 
                timestamp_ns: 0 
            };
        }
        nb_rx as usize
    }

    #[cfg(not(target_os = "linux"))]
    pub fn rx_burst<'a>(&self, _out: &mut [DpdkMbufViewMock]) -> usize {
        0
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Default)]
pub struct DpdkMbufViewMock;

#[cfg(not(target_os = "linux"))]
impl PacketView for DpdkMbufViewMock {
    fn timestamp_ns(&self) -> u64 { 0 }
    fn data(&self) -> &[u8] { &[] }
    fn ingress_ifindex(&self) -> Option<u32> { None }
    fn rss_queue_id(&self) -> Option<u16> { None }
}
