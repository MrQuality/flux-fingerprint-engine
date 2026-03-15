#[cfg(target_os = "linux")]
use flux_engine_core::PacketView;
#[cfg(target_os = "linux")]
use std::slice;

#[cfg(target_os = "linux")]
#[repr(C)]
pub struct rte_mbuf {
    pub buf_addr: *mut u8,
    pub buf_iova: u64,
    pub data_off: u16,
    pub refcnt: u16,
    pub nb_segs: u16,
    pub port: u16,
    pub ol_flags: u64,
    pub packet_type: u32,
    pub pkt_len: u32,
    pub data_len: u16,
    pub vlan_tci: u16,
    pub hash: u32,
}

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
            let data_ptr = mbuf.buf_addr.add(mbuf.data_off as usize);
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
            // hash.rss is typically what we want here
            Some(((*self.mbuf_ptr).hash % 65536) as u16)
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for DpdkMbufView {
    fn drop(&mut self) {
        // ADR-001 Mandate: Immediate Descriptor Release.
        // In a real build, we'd call `rte_pktmbuf_free(self.mbuf_ptr)` via dpdk-sys.
    }
}

#[cfg(target_os = "linux")]
pub struct DpdkDriver {
    pub port_id: u16,
}

#[cfg(target_os = "linux")]
impl DpdkDriver {
    pub fn rx_burst<'a>(&self, out: &mut [DpdkMbufView]) -> usize {
        // In a real implementation:
        // let mut mbuf_ptrs: [*mut rte_mbuf; 32] = [std::ptr::null_mut(); 32];
        // let nb_rx = unsafe { rte_eth_rx_burst(self.port_id, 0, mbuf_ptrs.as_mut_ptr() as *mut *mut std::ffi::c_void, out.len() as u16) };
        // for i in 0..nb_rx as usize {
        //     out[i] = DpdkMbufView { mbuf_ptr: mbuf_ptrs[i], timestamp_ns: 0 };
        // }
        // return nb_rx as usize;
        0
    }
}
