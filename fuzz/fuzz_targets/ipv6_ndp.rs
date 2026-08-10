#![no_main]
use libfuzzer_sys::fuzz_target;
use trapd_sensor_passive::frame::parse_ipv6;
use trapd_sensor_passive::icmpv6::parse_neighbor_discovery;

fuzz_target!(|data: &[u8]| {
    let _ = parse_ipv6(data);
    let _ = parse_neighbor_discovery(data);
});
