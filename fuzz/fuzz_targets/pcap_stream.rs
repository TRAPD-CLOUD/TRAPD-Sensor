#![no_main]
use libfuzzer_sys::fuzz_target;
use trapd_sensor_capture::fritzbox::PcapStreamDecoder;

fuzz_target!(|data: &[u8]| {
    // One-shot decode of the raw fuzz input, across standard, nanosecond,
    // and extended/Kuznetsov-modified pcap variants alike — the magic bytes
    // are part of `data`, so libfuzzer is free to discover all of them.
    let mut decoder = PcapStreamDecoder::new(65536);
    let _ = decoder.push(data);
    let _ = decoder.finish();

    // The same bytes fed back in varying-size chunks, to fuzz incremental
    // reassembly (arbitrary HTTP chunk boundaries) rather than only
    // one-shot parsing — this is how PcapStreamDecoder is actually driven
    // in production, from a streaming HTTP response.
    if let Some(&first) = data.first() {
        let chunk_len = 1 + (first as usize % 7);
        let mut decoder = PcapStreamDecoder::new(65536);
        for chunk in data.chunks(chunk_len) {
            if decoder.push(chunk).is_err() {
                break;
            }
        }
    }
});
