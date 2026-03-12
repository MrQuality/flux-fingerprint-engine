#![no_main]
use libfuzzer_sys::fuzz_target;
use flux_engine_core::PacketView;

struct FuzzPacket<'a> {
    data: &'a [u8],
}

impl<'a> PacketView for FuzzPacket<'a> {
    fn timestamp_ns(&self) -> u64 { 0 }
    fn data(&self) -> &[u8] { self.data }
}

fuzz_target!(|data: &[u8]| {
    let packet = FuzzPacket { data };
    // This will call the parser once implemented
    // let _ = flux_engine_core::parse_client_hello(&packet);
});
