#[cfg(target_os = "linux")]
use dpdk_sys::{rte_eth_rx_burst, rte_mbuf, rte_pktmbuf_free};
#[cfg(target_os = "linux")]
use flux_engine_core::PacketView;
#[cfg(target_os = "linux")]
use std::slice;

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
            // Access raw pointer directly from the mbuf payload
            let data_ptr = (mbuf.buf_addr as *mut u8).add(mbuf.data_off as usize);
            slice::from_raw_parts(data_ptr, mbuf.data_len as usize)
        }
    }

    fn ingress_ifindex(&self) -> Option<u32> {
        unsafe {
            if self.mbuf_ptr.is_null() {
                return None;
            }
            // Mbuf struct typically holds `port` which maps to interface index
            Some((*self.mbuf_ptr).port as u32)
        }
    }

    fn rss_queue_id(&self) -> Option<u16> {
        unsafe {
            if self.mbuf_ptr.is_null() {
                return None;
            }
            // In DPDK, actual queue ID isn't directly in mbuf, it's tied to the polling context.
            // We'll rely on the driver passing this context down.
            // For now, this requires the DpdkDriver to stamp the queue ID upon ingest,
            // similar to the AF_XDP driver redesign.
            None // Placeholder until stamped by ingest
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for DpdkMbufView {
    fn drop(&mut self) {
        if !self.mbuf_ptr.is_null() {
            unsafe {
                // Immediate descriptor release per MP-004 mandate
                rte_pktmbuf_free(self.mbuf_ptr);
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub struct DpdkDriver {
    pub port_id: u16,
    pub queue_id: u16, // Required for truthful metadata stamping
}

#[cfg(target_os = "linux")]
impl DpdkDriver {
    pub fn new(port_id: u16, queue_id: u16) -> Self {
        Self { port_id, queue_id }
    }

    /// Hot-path ingestion.
    ///
    /// Soundness: The closure strictly limits the borrow scope of the mbufs.
    pub fn ingest<F>(&self, max_packets: usize, mut f: F) -> usize
    where
        F: FnMut(&DpdkPacketView<'_>),
    {
        let mut mbuf_ptrs: [*mut rte_mbuf; 32] = [std::ptr::null_mut(); 32];
        let to_read = std::cmp::min(max_packets, 32) as u16;

        let nb_rx = unsafe {
            rte_eth_rx_burst(self.port_id, self.queue_id, mbuf_ptrs.as_mut_ptr(), to_read)
        };

        for i in 0..nb_rx as usize {
            let mbuf_ptr = mbuf_ptrs[i];

            unsafe {
                if mbuf_ptr.is_null() {
                    continue;
                }
                let mbuf = &*mbuf_ptr;
                let data_ptr = (mbuf.buf_addr as *mut u8).add(mbuf.data_off as usize);
                let data = slice::from_raw_parts(data_ptr, mbuf.data_len as usize);

                let view = DpdkPacketView {
                    data,
                    timestamp_ns: 0, // Would extract dynamic timestamp from mbuf if configured
                    ifindex: mbuf.port as u32,
                    queue_id: self.queue_id, // Stamping true polling queue
                };

                f(&view);

                // Immediate release
                rte_pktmbuf_free(mbuf_ptr);
            }
        }
        nb_rx as usize
    }
}

#[cfg(target_os = "linux")]
pub struct DpdkPacketView<'a> {
    pub data: &'a [u8],
    pub timestamp_ns: u64,
    pub ifindex: u32,
    pub queue_id: u16,
}

#[cfg(target_os = "linux")]
impl<'a> PacketView for DpdkPacketView<'a> {
    fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }
    fn data(&self) -> &[u8] {
        self.data
    }
    fn ingress_ifindex(&self) -> Option<u32> {
        Some(self.ifindex)
    }
    fn rss_queue_id(&self) -> Option<u16> {
        Some(self.queue_id)
    }
}
