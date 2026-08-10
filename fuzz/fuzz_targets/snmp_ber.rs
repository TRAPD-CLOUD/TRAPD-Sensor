#![no_main]
use libfuzzer_sys::fuzz_target;
use trapd_sensor_active::snmp::parse_response;

fuzz_target!(|data: &[u8]| {
    let _ = parse_response(data, b"synthetic", 42);
});
