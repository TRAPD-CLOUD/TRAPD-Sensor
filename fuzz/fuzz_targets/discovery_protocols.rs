#![no_main]
use libfuzzer_sys::fuzz_target;
use trapd_sensor_passive::{dhcp::parse_dhcp, dns::parse_dns, ssdp::parse_ssdp};

fuzz_target!(|data: &[u8]| {
    let _ = parse_dhcp(data);
    let _ = parse_dns(data);
    let _ = parse_ssdp(data);
});
