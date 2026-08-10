#![no_main]
use libfuzzer_sys::fuzz_target;
use trapd_sensor_core::config::SensorConfig;
use trapd_sensor_passive::frame::{parse_ethernet, parse_ipv4, parse_ipv6};
use trapd_sensor_passive::PassiveObserver;

fuzz_target!(|data: &[u8]| {
    let _ = parse_ethernet(data);
    let _ = parse_ipv4(data);
    let _ = parse_ipv6(data);
    let mut observer = PassiveObserver::new("fuzz0", SensorConfig::default().effective_policy(), 60, 128);
    let _ = observer.handle_frame(data, chrono::DateTime::UNIX_EPOCH);
});
