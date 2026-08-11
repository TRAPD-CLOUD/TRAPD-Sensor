//! Incremental classic-pcap decoder.
//!
//! # Format provenance
//!
//! Verified against libpcap's own reference reader (`sf-pcap.c`,
//! `the-tcpdump-group/libpcap`) and Wireshark's `wiretap/libpcap.h`, not
//! reconstructed from assumptions. See `docs/fritzbox.md` for the
//! investigation this decoder's [`PcapVariant::Extended`] support came from.
//!
//! Every variant recognized here shares one 24-byte global (file) header:
//! `magic`(4) `version_major`(2) `version_minor`(2) `thiszone`(4)
//! `sigfigs`(4) `snaplen`(4) `linktype`(4) — all in the file's own byte
//! order, indicated by which magic byte sequence matched. Only the
//! per-packet record header differs between variants; see [`PcapVariant`].

use thiserror::Error;

/// Size of the classic-pcap global (file) header — identical for every
/// magic number this decoder recognizes.
const GLOBAL: usize = 24;
/// Size of a [`PcapVariant::Standard`] per-packet record header: `ts_sec`,
/// `ts_usec`/`ts_nsec`, `incl_len`, `orig_len`, each a 4-byte field.
const RECORD: usize = 16;
/// Size of a [`PcapVariant::Extended`] per-packet record header: the
/// standard 16 bytes above, plus `ifindex`(4) `protocol`(2) `pkt_type`(1)
/// `pad`(1) — see [`PcapVariant::Extended`] and [`ExtendedRecordMeta`].
const RECORD_EXTENDED: usize = 24;
/// `LINKTYPE_ETHERNET`, the only link type TRAPD's passive pipeline accepts.
/// Enforced by the FRITZ!Box capture callers (`sensor-cli`, `sensor-daemon`),
/// not by this decoder — see the module-level note on that split below.
pub const LINKTYPE_ETHERNET: u32 = 1;
/// libpcap's `sf-pcap.c` notes that an Extended/Kuznetsov-modified capture
/// with `LINKTYPE_ETHERNET` may have been taken in "cooked mode", with a
/// synthetic 14-byte Ethernet header spliced on at capture time; that makes
/// a single record's `incl_len` legitimately exceed the file's declared
/// `snaplen` by up to one Ethernet header's worth of bytes. Applied only to
/// [`PcapVariant::Extended`] + [`LINKTYPE_ETHERNET`]; every other
/// combination keeps the strict `incl_len <= snaplen` bound.
const EXTENDED_ETHERNET_SNAPLEN_SLACK: u32 = 14;

/// Byte order of every multi-byte field in this capture. Determined by which
/// of the recognized magic-number byte sequences matched — see
/// [`detect_format`] — since "libpcap" files are written in the byte order
/// of the host that wrote them, with no separate byte-order marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}

impl std::fmt::Display for Endianness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Endianness::Little => "little",
            Endianness::Big => "big",
        })
    }
}

/// Per-packet timestamp precision, determined by the file's magic number.
/// Not currently converted or consumed downstream — see
/// [`PcapPacket::timestamp_fraction`] — so this is exposed rather than
/// assumed, to avoid silently misinterpreting nanoseconds as microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampPrecision {
    Microseconds,
    Nanoseconds,
}

impl std::fmt::Display for TimestampPrecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TimestampPrecision::Microseconds => "microseconds",
            TimestampPrecision::Nanoseconds => "nanoseconds",
        })
    }
}

/// Which classic-pcap per-packet record layout this stream uses.
///
/// Both variants share the identical 24-byte global header described at the
/// top of this file — only the *per-packet record* header differs.
///
/// # `Standard`
///
/// Magic `0xa1b2c3d4` (`TCPDUMP_MAGIC`, microsecond timestamps) or
/// `0xa1b23c4d` (`NSEC_TCPDUMP_MAGIC`, nanosecond timestamps) — the format
/// every modern pcap writer produces (tcpdump, Wireshark/dumpcap, libpcap's
/// own writer). 16-byte record header: `ts_sec`, `ts_usec`/`ts_nsec`,
/// `incl_len`, `orig_len`; the packet's captured bytes follow directly.
///
/// # `Extended`
///
/// Magic `0xa1b2cd34` — `KUZNETZOV_TCPDUMP_MAGIC` in libpcap's own
/// `sf-pcap.c`, i.e. Alexey Kuznetsov's modified libpcap record format,
/// historically emitted by patched libpcap builds (e.g. Red Hat 6.1/6.2).
/// Confirmed by this investigation to also be what FRITZ!OS's bundled
/// tcpdump/libpcap emits from `cgi-bin/capture_notimeout` and the
/// `fritz.box/#/cap` capture UI: a capture downloaded directly from the
/// router's own UI, independently verified with Linux `file(1)`
/// ("pcap capture file, microsecond ts, extensions (little-endian)"),
/// begins with the identical `34 cd b2 a1` bytes this decoder now accepts.
/// This is a real, if old, libpcap-compatible format — not corrupted or
/// truncated standard pcap.
///
/// 24-byte record header, per libpcap's `struct pcap_sf_patched_pkthdr`
/// (`sf-pcap.c`) / Wireshark's `struct pcaprec_modified_hdr`
/// (`wiretap/libpcap.h`): the standard 16 bytes above, plus `ifindex` (u32),
/// `protocol` (u16), `pkt_type` (u8), `pad` (u8) — see
/// [`ExtendedRecordMeta`]. Always microsecond precision; there is no
/// nanosecond magic for this variant.
///
/// Critically — verified against libpcap's own reader, which is the
/// authority here, not just a byte-counting guess against one sample
/// — `incl_len`/`orig_len` describe *only* the Ethernet frame that follows
/// the full 24-byte header, the same as [`Standard`](PcapVariant::Standard).
/// libpcap reads the entire 24-byte `pcap_sf_patched_pkthdr` first
/// (`ps->hdrsize = sizeof(struct pcap_sf_patched_pkthdr)`), then reads
/// exactly `caplen` more bytes as the untouched frame
/// (`fread(p->buffer, 1, hdr->caplen, fp)`). No arithmetic adjustment to
/// `incl_len` — such as subtracting the 8 extra header bytes — is needed or
/// correct; that would double-count them, since they are already consumed
/// by the wider 24-byte header read.
///
/// Other historical magic numbers exist in libpcap's `sf-pcap.c`
/// (`FMESQUITA_TCPDUMP_MAGIC` 0xa1b234cd, `NAVTEL_TCPDUMP_MAGIC` 0xa12b3c4d,
/// `CBPF_SAVEFILE_MAGIC` 0xa1b2c3cb) but are reserved/vendor-specific
/// formats libpcap itself does not fully support reading either; FRITZ!OS
/// does not emit them, so they are intentionally not recognized here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapVariant {
    Standard,
    Extended,
}

impl PcapVariant {
    fn record_header_len(self) -> usize {
        match self {
            PcapVariant::Standard => RECORD,
            PcapVariant::Extended => RECORD_EXTENDED,
        }
    }
}

impl std::fmt::Display for PcapVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PcapVariant::Standard => "standard",
            PcapVariant::Extended => "extended",
        })
    }
}

/// The [`PcapVariant::Extended`] per-record metadata that precedes the
/// Ethernet frame, per libpcap's `struct pcap_sf_patched_pkthdr`. TRAPD's
/// passive pipeline does not currently consume these fields — they are
/// parsed explicitly and named rather than treated as an opaque skip, so a
/// future consumer has correct values instead of undocumented filler bytes,
/// and so a change to their meaning would be visible in one place.
///
/// The values themselves have no validity constraint (any bit pattern is
/// structurally well-formed), so there is nothing to reject here beyond
/// having the bytes available at all, which the record-header length check
/// already guarantees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtendedRecordMeta {
    /// Index of the capturing interface on the capturing host (`int index`
    /// in libpcap's `pcap_sf_patched_pkthdr`).
    pub ifindex: u32,
    /// Kernel-reported protocol/family value associated with the packet.
    pub protocol: u16,
    /// Linux `PACKET_*` type (host/broadcast/multicast/otherhost/outgoing).
    pub pkt_type: u8,
    /// Alignment padding; carries no information.
    pub pad: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PcapPacket {
    pub timestamp_seconds: u32,
    /// Sub-second component: microseconds, or nanoseconds if the decoder's
    /// [`PcapStreamDecoder::timestamp_precision`] reports
    /// [`TimestampPrecision::Nanoseconds`]. Not currently consumed
    /// downstream, so no (potentially lossy) unit conversion happens here —
    /// a future caller that needs the value must interpret it using the
    /// reported precision rather than assuming microseconds.
    pub timestamp_fraction: u32,
    pub original_len: u32,
    /// Present only for [`PcapVariant::Extended`] records.
    pub extended_meta: Option<ExtendedRecordMeta>,
    pub data: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PcapError {
    #[error("unsupported PCAP magic (not standard, nanosecond, or extended classic pcap)")]
    UnsupportedMagic,
    #[error("unsupported PCAP version (only major version 2 is recognized)")]
    UnsupportedVersion,
    #[error("PCAP snapshot length exceeds configured bound")]
    SnapshotTooLarge,
    #[error("PCAP record is empty (zero-length capture)")]
    EmptyRecord,
    #[error("captured packet exceeds the file's declared snapshot length")]
    RecordExceedsSnaplen,
    #[error("captured packet exceeds configured limit")]
    RecordExceedsConfiguredLimit,
    #[error("captured length exceeds the packet's original on-wire length")]
    CapturedLongerThanOriginal,
    #[error("PCAP stream ended in a truncated global header")]
    TruncatedGlobalHeader,
    #[error("PCAP stream ended in a truncated packet record")]
    TruncatedRecord,
    #[error("PCAP receive buffer limit exceeded")]
    BufferLimit,
}

/// Matches a magic-number byte sequence against every classic-pcap variant
/// this decoder recognizes, returning its endianness, record-layout variant,
/// and timestamp precision in one step. See [`PcapVariant`] for the
/// authoritative justification of each entry.
fn detect_format(magic: [u8; 4]) -> Option<(Endianness, PcapVariant, TimestampPrecision)> {
    use Endianness::{Big, Little};
    use PcapVariant::{Extended, Standard};
    use TimestampPrecision::{Microseconds, Nanoseconds};
    match magic {
        // TCPDUMP_MAGIC (0xa1b2c3d4), written in the file's own byte order.
        [0xd4, 0xc3, 0xb2, 0xa1] => Some((Little, Standard, Microseconds)),
        [0xa1, 0xb2, 0xc3, 0xd4] => Some((Big, Standard, Microseconds)),
        // NSEC_TCPDUMP_MAGIC (0xa1b23c4d).
        [0x4d, 0x3c, 0xb2, 0xa1] => Some((Little, Standard, Nanoseconds)),
        [0xa1, 0xb2, 0x3c, 0x4d] => Some((Big, Standard, Nanoseconds)),
        // KUZNETZOV_TCPDUMP_MAGIC (0xa1b2cd34) — see `PcapVariant::Extended`.
        [0x34, 0xcd, 0xb2, 0xa1] => Some((Little, Extended, Microseconds)),
        [0xa1, 0xb2, 0xcd, 0x34] => Some((Big, Extended, Microseconds)),
        _ => None,
    }
}

fn extended_snaplen_slack(variant: PcapVariant, link_type: Option<u32>) -> u32 {
    if variant == PcapVariant::Extended && link_type == Some(LINKTYPE_ETHERNET) {
        EXTENDED_ETHERNET_SNAPLEN_SLACK
    } else {
        0
    }
}

/// Incremental classic-pcap decoder. `push` accepts arbitrary transport
/// fragmentation — including splits inside the magic number, inside either
/// header, or inside a frame — and always produces the same packets
/// regardless of how the input was chunked. The allocation is capped at
/// max(global-header, largest record-header) + one maximum packet; consumed
/// prefixes are drained before accepting more bytes, so an endless stream
/// that never completes a header/record cannot grow the buffer without
/// bound.
///
/// Outputs the same [`PcapPacket`] shape — a decoded Ethernet frame plus
/// metadata — regardless of [`PcapVariant`]; callers do not need
/// variant-specific handling (see `docs/fritzbox.md`).
pub struct PcapStreamDecoder {
    buffer: Vec<u8>,
    endian: Option<Endianness>,
    variant: Option<PcapVariant>,
    timestamp_precision: Option<TimestampPrecision>,
    max_packet: usize,
    snaplen: u32,
    link_type: Option<u32>,
}
impl PcapStreamDecoder {
    pub fn new(max_packet: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(max_packet.min(65536) + RECORD_EXTENDED),
            endian: None,
            variant: None,
            timestamp_precision: None,
            max_packet,
            snaplen: 0,
            link_type: None,
        }
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<PcapPacket>, PcapError> {
        // Worst-case simultaneous buffering need: the largest of (a) the
        // global header while the variant is still unknown, or (b) the
        // largest record header plus one full max-size packet, once past
        // the global header. GLOBAL and RECORD_EXTENDED are both 24 bytes,
        // so `.max()` here is a documented equality, not a coincidence to
        // silently rely on.
        let limit = self
            .max_packet
            .checked_add(GLOBAL.max(RECORD_EXTENDED))
            .ok_or(PcapError::BufferLimit)?;
        let mut packets = Vec::new();
        let mut remaining = bytes;

        while !remaining.is_empty() {
            let available = limit
                .checked_sub(self.buffer.len())
                .ok_or(PcapError::BufferLimit)?;
            if available == 0 {
                return Err(PcapError::BufferLimit);
            }
            let accepted = available.min(remaining.len());
            self.buffer.extend_from_slice(&remaining[..accepted]);
            remaining = &remaining[accepted..];
            self.decode_available(&mut packets)?;
        }

        Ok(packets)
    }

    fn decode_available(&mut self, packets: &mut Vec<PcapPacket>) -> Result<(), PcapError> {
        if self.endian.is_none() {
            if self.buffer.len() < GLOBAL {
                return Ok(());
            }
            let magic = [
                self.buffer[0],
                self.buffer[1],
                self.buffer[2],
                self.buffer[3],
            ];
            let (endian, variant, precision) =
                detect_format(magic).ok_or(PcapError::UnsupportedMagic)?;
            if read16(&self.buffer[4..6], endian) != 2 {
                return Err(PcapError::UnsupportedVersion);
            }
            let snaplen = read32(&self.buffer[16..20], endian);
            if snaplen == 0 || snaplen as usize > self.max_packet {
                return Err(PcapError::SnapshotTooLarge);
            }
            self.link_type = Some(read32(&self.buffer[20..24], endian));
            self.endian = Some(endian);
            self.variant = Some(variant);
            self.timestamp_precision = Some(precision);
            self.snaplen = snaplen;
            self.buffer.drain(..GLOBAL);
        }
        let endian = self.endian.unwrap();
        let variant = self.variant.unwrap();
        let header_len = variant.record_header_len();
        let declared_limit = self
            .snaplen
            .saturating_add(extended_snaplen_slack(variant, self.link_type));

        loop {
            if self.buffer.len() < header_len {
                break;
            }
            let cap = read32(&self.buffer[8..12], endian);
            let original = read32(&self.buffer[12..16], endian);
            if cap == 0 {
                return Err(PcapError::EmptyRecord);
            }
            if cap as usize > self.max_packet {
                return Err(PcapError::RecordExceedsConfiguredLimit);
            }
            if cap > declared_limit {
                return Err(PcapError::RecordExceedsSnaplen);
            }
            if cap > original {
                return Err(PcapError::CapturedLongerThanOriginal);
            }
            let total = header_len + cap as usize;
            if self.buffer.len() < total {
                break;
            }
            let extended_meta = (variant == PcapVariant::Extended).then(|| ExtendedRecordMeta {
                ifindex: read32(&self.buffer[16..20], endian),
                protocol: read16(&self.buffer[20..22], endian),
                pkt_type: self.buffer[22],
                pad: self.buffer[23],
            });
            packets.push(PcapPacket {
                timestamp_seconds: read32(&self.buffer[0..4], endian),
                timestamp_fraction: read32(&self.buffer[4..8], endian),
                original_len: original,
                extended_meta,
                data: self.buffer[header_len..total].to_vec(),
            });
            self.buffer.drain(..total);
        }
        Ok(())
    }
    pub fn finish(self) -> Result<(), PcapError> {
        if self.buffer.is_empty() && self.endian.is_some() {
            Ok(())
        } else if self.endian.is_none() {
            Err(PcapError::TruncatedGlobalHeader)
        } else {
            Err(PcapError::TruncatedRecord)
        }
    }
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
    pub fn link_type(&self) -> Option<u32> {
        self.link_type
    }
    /// `None` until the global header has been parsed.
    pub fn endian(&self) -> Option<Endianness> {
        self.endian
    }
    /// `None` until the global header has been parsed.
    pub fn variant(&self) -> Option<PcapVariant> {
        self.variant
    }
    /// `None` until the global header has been parsed.
    pub fn timestamp_precision(&self) -> Option<TimestampPrecision> {
        self.timestamp_precision
    }
    /// `None` until the global header has been parsed.
    pub fn snaplen(&self) -> Option<u32> {
        self.endian.is_some().then_some(self.snaplen)
    }
}
fn read16(b: &[u8], e: Endianness) -> u16 {
    match e {
        Endianness::Little => u16::from_le_bytes([b[0], b[1]]),
        Endianness::Big => u16::from_be_bytes([b[0], b[1]]),
    }
}
fn read32(b: &[u8], e: Endianness) -> u32 {
    match e {
        Endianness::Little => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        Endianness::Big => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal, clearly-synthetic Ethernet+ARP frame (broadcast MACs,
    /// RFC 5737/private-range-style addresses) reused as packet payload
    /// across tests — same convention already used in
    /// `sensor-daemon`'s FRITZ!Box fixture.
    const ARP_FRAME: [u8; 42] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 1, 2, 3, 4, 5, 0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0,
        2, 0, 1, 2, 3, 4, 5, 192, 168, 1, 2, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1,
    ];

    fn global_header_le_standard_usec(snaplen: u32, linktype: u32) -> Vec<u8> {
        let mut v = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        v.extend(snaplen.to_le_bytes());
        v.extend(linktype.to_le_bytes());
        v
    }

    fn standard_record_le(data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(1u32.to_le_bytes()); // ts_sec
        v.extend(2u32.to_le_bytes()); // ts_usec
        v.extend((data.len() as u32).to_le_bytes()); // incl_len
        v.extend((data.len() as u32).to_le_bytes()); // orig_len
        v.extend(data);
        v
    }

    fn stream() -> Vec<u8> {
        let mut v = global_header_le_standard_usec(64, 1);
        v.extend(standard_record_le(b"abc"));
        v.extend(standard_record_le(b"defg"));
        v
    }

    // --- standard variant: existing coverage, preserved ---

    #[test]
    fn every_fragmentation_boundary() {
        let bytes = stream();
        for size in 1..=bytes.len() {
            let mut d = PcapStreamDecoder::new(64);
            let mut all = vec![];
            for c in bytes.chunks(size) {
                all.extend(d.push(c).unwrap())
            }
            assert_eq!(all.len(), 2);
            d.finish().unwrap();
        }
    }
    #[test]
    fn multiple_records_one_chunk() {
        assert_eq!(PcapStreamDecoder::new(64).push(&stream()).unwrap().len(), 2)
    }
    #[test]
    fn chunk_larger_than_receive_buffer_is_consumed_incrementally() {
        let mut bytes = stream();
        let records = bytes.split_off(GLOBAL);
        for _ in 0..10 {
            bytes.extend_from_slice(&records);
        }
        assert!(bytes.len() > 64 + GLOBAL + RECORD);
        assert_eq!(PcapStreamDecoder::new(64).push(&bytes).unwrap().len(), 20);
    }
    #[test]
    fn standard_variant_and_endian_are_reported() {
        let mut d = PcapStreamDecoder::new(64);
        d.push(&stream()).unwrap();
        assert_eq!(d.variant(), Some(PcapVariant::Standard));
        assert_eq!(
            d.timestamp_precision(),
            Some(TimestampPrecision::Microseconds)
        );
        assert_eq!(d.snaplen(), Some(64));
        assert_eq!(d.link_type(), Some(1));
    }

    // --- global header validation ---

    #[test]
    fn oversized_snaplen() {
        let mut b = stream();
        b[16] = 65;
        assert_eq!(
            PcapStreamDecoder::new(64).push(&b),
            Err(PcapError::SnapshotTooLarge)
        );
    }
    #[test]
    fn unsupported_magic_is_rejected_cleanly() {
        let b = vec![0u8; GLOBAL];
        assert_eq!(
            PcapStreamDecoder::new(64).push(&b),
            Err(PcapError::UnsupportedMagic)
        );
    }
    #[test]
    fn unsupported_version_is_rejected() {
        let mut b = global_header_le_standard_usec(64, 1);
        b[4] = 9; // version_major = 9
        assert_eq!(
            PcapStreamDecoder::new(64).push(&b),
            Err(PcapError::UnsupportedVersion)
        );
    }
    #[test]
    fn truncated_global_header_at_eof() {
        let b = stream();
        let mut d = PcapStreamDecoder::new(64);
        d.push(&b[..GLOBAL - 1]).unwrap();
        assert_eq!(d.finish(), Err(PcapError::TruncatedGlobalHeader));
    }
    #[test]
    fn truncated_record_at_eof() {
        let b = stream();
        let mut d = PcapStreamDecoder::new(64);
        d.push(&b[..30]).unwrap();
        assert_eq!(d.finish(), Err(PcapError::TruncatedRecord));
    }
    #[test]
    fn non_ethernet_linktype_is_reported_not_rejected() {
        // The decoder is link-type-agnostic by design; enforcing
        // LINKTYPE_ETHERNET is the caller's job (sensor-cli / sensor-daemon).
        let mut b = global_header_le_standard_usec(64, 105); // DLT_IEEE802_11
        b.extend(standard_record_le(b"abc"));
        let mut d = PcapStreamDecoder::new(64);
        let packets = d.push(&b).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(d.link_type(), Some(105));
    }

    // --- per-record validation ---

    #[test]
    fn empty_record_is_rejected() {
        let mut b = global_header_le_standard_usec(64, 1);
        b.extend(standard_record_le(&[]));
        assert_eq!(
            PcapStreamDecoder::new(64).push(&b),
            Err(PcapError::EmptyRecord)
        );
    }
    #[test]
    fn record_exceeding_configured_limit_is_rejected() {
        let mut b = global_header_le_standard_usec(64, 1);
        b.extend(standard_record_le(&[0u8; 65])); // > max_packet(64), <= snaplen? irrelevant, checked first
        assert_eq!(
            PcapStreamDecoder::new(64).push(&b),
            Err(PcapError::RecordExceedsConfiguredLimit)
        );
    }
    #[test]
    fn record_exceeding_declared_snaplen_is_rejected() {
        let mut b = global_header_le_standard_usec(40, 1); // snaplen=40, max_packet=64
        b.extend(standard_record_le(&[0u8; 41])); // > snaplen(40), <= max_packet(64)
        assert_eq!(
            PcapStreamDecoder::new(64).push(&b),
            Err(PcapError::RecordExceedsSnaplen)
        );
    }
    #[test]
    fn captured_longer_than_original_is_rejected() {
        let mut b = global_header_le_standard_usec(64, 1);
        b.extend(3u32.to_le_bytes()); // ts_sec
        b.extend(4u32.to_le_bytes()); // ts_usec
        b.extend(10u32.to_le_bytes()); // incl_len
        b.extend(5u32.to_le_bytes()); // orig_len < incl_len
        b.extend([0u8; 10]);
        assert_eq!(
            PcapStreamDecoder::new(64).push(&b),
            Err(PcapError::CapturedLongerThanOriginal)
        );
    }
    #[test]
    fn malformed_record_length_matches_first_violated_bound() {
        let mut b = stream();
        b[32] = 100; // first record's incl_len becomes 100
        assert_eq!(
            PcapStreamDecoder::new(64).push(&b),
            Err(PcapError::RecordExceedsConfiguredLimit)
        );
    }

    // --- extended (Kuznetsov-modified, FRITZ!Box) variant ---

    fn extended_record_le(
        ifindex: u32,
        protocol: u16,
        pkt_type: u8,
        pad: u8,
        data: &[u8],
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(11u32.to_le_bytes()); // ts_sec
        v.extend(222_222u32.to_le_bytes()); // ts_usec
        v.extend((data.len() as u32).to_le_bytes()); // incl_len == frame length, no adjustment
        v.extend((data.len() as u32).to_le_bytes()); // orig_len
        v.extend(ifindex.to_le_bytes());
        v.extend(protocol.to_le_bytes());
        v.push(pkt_type);
        v.push(pad);
        v.extend(data);
        v
    }

    fn extended_global_header_le(snaplen: u32, linktype: u32) -> Vec<u8> {
        let mut v = vec![0x34, 0xcd, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        v.extend(snaplen.to_le_bytes());
        v.extend(linktype.to_le_bytes());
        v
    }

    /// Regression fixture for the real FRITZ!Box capture: this is the exact
    /// 24-byte global header this investigation captured from a FRITZ!Box
    /// 5590 Fiber (`fritz.box/#/cap`, downloaded as
    /// `fritzbox-vcc0_11.08.26_1736.eth`, `file(1)`: "pcap capture file,
    /// microsecond ts, extensions (little-endian) - version 2.4 (Ethernet,
    /// capture length 2048)"). The per-packet body below is a synthetic
    /// stand-in built to the same verified record layout — deliberately not
    /// the router's actual captured traffic, to avoid committing a real
    /// device's MAC/IP addresses to the repository.
    #[test]
    fn extended_fritzbox_regression_fixture() {
        let mut b = vec![
            0x34, 0xcd, 0xb2, 0xa1, // magic
            0x02, 0x00, 0x04, 0x00, // version 2.4
            0x00, 0x00, 0x00, 0x00, // thiszone
            0x00, 0x00, 0x00, 0x00, // sigfigs
            0x00, 0x08, 0x00, 0x00, // snaplen = 2048
            0x01, 0x00, 0x00, 0x00, // linktype = LINKTYPE_ETHERNET
        ];
        assert_eq!(b.len(), GLOBAL);
        // pkt_type = 4 (PACKET_OUTGOING) matches the real capture's first
        // record, itself consistent with an outgoing packet on a WAN vantage
        // point interface.
        b.extend(extended_record_le(0, 1, 4, 0, &ARP_FRAME));

        let mut d = PcapStreamDecoder::new(2048);
        let packets = d.push(&b).unwrap();

        assert_eq!(d.variant(), Some(PcapVariant::Extended));
        assert_eq!(
            d.timestamp_precision(),
            Some(TimestampPrecision::Microseconds)
        );
        assert_eq!(d.snaplen(), Some(2048));
        assert_eq!(d.link_type(), Some(LINKTYPE_ETHERNET));
        d.finish().unwrap();

        assert_eq!(packets.len(), 1);
        // The extracted frame must be byte-for-byte the real Ethernet frame,
        // with no leftover extended-header bytes and nothing truncated.
        assert_eq!(packets[0].data, ARP_FRAME);
        assert_eq!(packets[0].original_len, ARP_FRAME.len() as u32);
        assert_eq!(
            packets[0].extended_meta,
            Some(ExtendedRecordMeta {
                ifindex: 0,
                protocol: 1,
                pkt_type: 4,
                pad: 0,
            })
        );
    }

    #[test]
    fn extended_little_endian_multiple_packets_with_different_lengths() {
        let mut b = extended_global_header_le(2048, LINKTYPE_ETHERNET);
        let small = [0xAAu8; 10];
        let large = [0xBBu8; 200];
        b.extend(extended_record_le(0, 1, 0, 0, &ARP_FRAME));
        b.extend(extended_record_le(1, 2, 4, 0, &small));
        b.extend(extended_record_le(2, 3, 3, 0, &large));

        let mut d = PcapStreamDecoder::new(2048);
        let packets = d.push(&b).unwrap();
        d.finish().unwrap();

        // A wrong extended-header size would let the first record decode
        // "successfully" while desynchronizing every record after it — so
        // this checks exact content, not just count, for every packet.
        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0].data, ARP_FRAME);
        assert_eq!(packets[1].data, small);
        assert_eq!(packets[2].data, large);
        assert_eq!(
            packets[1].extended_meta,
            Some(ExtendedRecordMeta {
                ifindex: 1,
                protocol: 2,
                pkt_type: 4,
                pad: 0,
            })
        );
    }

    #[test]
    fn extended_big_endian_variant_decodes() {
        let mut b = vec![0xa1, 0xb2, 0xcd, 0x34, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0];
        b.extend(2048u32.to_be_bytes());
        b.extend(LINKTYPE_ETHERNET.to_be_bytes());
        let mut rec = Vec::new();
        rec.extend(1u32.to_be_bytes());
        rec.extend(2u32.to_be_bytes());
        rec.extend((ARP_FRAME.len() as u32).to_be_bytes());
        rec.extend((ARP_FRAME.len() as u32).to_be_bytes());
        rec.extend(7u32.to_be_bytes()); // ifindex
        rec.extend(9u16.to_be_bytes()); // protocol
        rec.push(4); // pkt_type
        rec.push(0); // pad
        rec.extend(ARP_FRAME);
        b.extend(rec);

        let mut d = PcapStreamDecoder::new(2048);
        let packets = d.push(&b).unwrap();
        assert_eq!(d.variant(), Some(PcapVariant::Extended));
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].data, ARP_FRAME);
        assert_eq!(
            packets[0].extended_meta,
            Some(ExtendedRecordMeta {
                ifindex: 7,
                protocol: 9,
                pkt_type: 4,
                pad: 0,
            })
        );
    }

    #[test]
    fn extended_every_fragmentation_boundary() {
        let mut b = extended_global_header_le(2048, LINKTYPE_ETHERNET);
        b.extend(extended_record_le(0, 1, 4, 0, &ARP_FRAME));
        b.extend(extended_record_le(1, 2, 0, 0, &[0xCCu8; 30]));
        for size in 1..=b.len() {
            let mut d = PcapStreamDecoder::new(2048);
            let mut all = vec![];
            for c in b.chunks(size) {
                all.extend(d.push(c).unwrap());
            }
            assert_eq!(all.len(), 2, "chunk size {size}");
            assert_eq!(all[0].data, ARP_FRAME, "chunk size {size}");
            assert_eq!(all[1].data, [0xCCu8; 30], "chunk size {size}");
            d.finish().unwrap();
        }
    }
    #[test]
    fn split_inside_extended_packet_header() {
        let mut b = extended_global_header_le(2048, LINKTYPE_ETHERNET);
        b.extend(extended_record_le(0, 1, 4, 0, &ARP_FRAME));
        // GLOBAL (24) + 20 bytes into the 24-byte extended record header —
        // i.e. mid ifindex/protocol/pkt_type/pad, past the standard 16.
        let split = GLOBAL + 20;
        let mut d = PcapStreamDecoder::new(2048);
        let mut all = d.push(&b[..split]).unwrap();
        assert!(all.is_empty());
        all.extend(d.push(&b[split..]).unwrap());
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].data, ARP_FRAME);
    }
    #[test]
    fn one_extended_packet_across_many_single_byte_chunks() {
        let mut b = extended_global_header_le(2048, LINKTYPE_ETHERNET);
        b.extend(extended_record_le(0, 1, 4, 0, &ARP_FRAME));
        let mut d = PcapStreamDecoder::new(2048);
        let mut all = vec![];
        for byte in &b {
            all.extend(d.push(&[*byte]).unwrap());
        }
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].data, ARP_FRAME);
    }

    #[test]
    fn extended_record_exceeding_snaplen_gets_cooked_mode_slack() {
        // snaplen=100; a genuine Ethernet-DLT extended capture may carry a
        // synthetic 14-byte cooked-mode header, so incl_len up to 114 must
        // still be accepted (see EXTENDED_ETHERNET_SNAPLEN_SLACK).
        let mut b = extended_global_header_le(114, LINKTYPE_ETHERNET);
        b[16..20].copy_from_slice(&100u32.to_le_bytes()); // snaplen = 100
        b.extend(extended_record_le(0, 1, 4, 0, &[0u8; 114]));
        assert_eq!(PcapStreamDecoder::new(200).push(&b).unwrap().len(), 1);
    }
    #[test]
    fn extended_record_beyond_slack_is_still_rejected() {
        let mut b = extended_global_header_le(200, LINKTYPE_ETHERNET);
        b[16..20].copy_from_slice(&100u32.to_le_bytes()); // snaplen = 100
        b.extend(extended_record_le(0, 1, 4, 0, &[0u8; 115])); // 100 + 14 slack + 1
        assert_eq!(
            PcapStreamDecoder::new(200).push(&b),
            Err(PcapError::RecordExceedsSnaplen)
        );
    }
    #[test]
    fn standard_variant_gets_no_slack() {
        // The same 14-byte overshoot must NOT be tolerated for the standard
        // variant — the slack is specifically an Extended/cooked-mode fact,
        // not a general fudge factor.
        let mut b = global_header_le_standard_usec(100, LINKTYPE_ETHERNET);
        b.extend(standard_record_le(&[0u8; 114]));
        assert_eq!(
            PcapStreamDecoder::new(200).push(&b),
            Err(PcapError::RecordExceedsSnaplen)
        );
    }

    // --- robustness / never-panics coverage ---

    /// Tiny deterministic xorshift PRNG — avoids adding a `rand`/`proptest`
    /// dependency for what is a handful of bounded parser-robustness checks.
    struct Xorshift(u64);
    impl Xorshift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| (self.next() & 0xff) as u8).collect()
        }
    }

    #[test]
    fn never_panics_on_arbitrary_short_buffers() {
        let mut rng = Xorshift(0x9E3779B97F4A7C15);
        for len in 0..80 {
            for _ in 0..20 {
                let buf = rng.bytes(len);
                let mut d = PcapStreamDecoder::new(2048);
                let _ = d.push(&buf);
                let _ = d.finish();
            }
        }
    }
    #[test]
    fn never_panics_on_random_magic_bytes() {
        let mut rng = Xorshift(0xD1B54A32D192ED03);
        for _ in 0..500 {
            let mut buf = vec![0u8; GLOBAL];
            buf[..4].copy_from_slice(&rng.bytes(4));
            let mut d = PcapStreamDecoder::new(2048);
            let _ = d.push(&buf);
        }
        // A handful of specific known other-format magics/near-misses, to
        // make sure they're cleanly rejected rather than misclassified.
        for magic in [
            [0x0A, 0x0D, 0x0D, 0x0A], // pcapng section header block
            [0x1F, 0x8B, 0x00, 0x00], // gzip
            [0x89, 0x50, 0x4E, 0x47], // PNG
            [0xD4, 0xC3, 0xB2, 0xa0], // one bit off from TCPDUMP_MAGIC(LE)
            [0x00, 0x00, 0x00, 0x00],
            [0xff, 0xff, 0xff, 0xff],
        ] {
            let mut buf = vec![0u8; GLOBAL];
            buf[..4].copy_from_slice(&magic);
            assert_eq!(
                PcapStreamDecoder::new(2048).push(&buf),
                Err(PcapError::UnsupportedMagic)
            );
        }
    }
    #[test]
    fn never_panics_on_random_incl_len_and_orig_len() {
        let mut rng = Xorshift(0x2545F4914F6CDD1D);
        for _ in 0..300 {
            let mut b = extended_global_header_le(2048, LINKTYPE_ETHERNET);
            b.extend(rng.bytes(8)); // ts_sec, ts_usec: any value is legal
            b.extend(rng.bytes(4)); // incl_len: arbitrary
            b.extend(rng.bytes(4)); // orig_len: arbitrary
            b.extend(rng.bytes(8)); // ifindex, protocol/pkt_type/pad
            b.extend(rng.bytes(16)); // a little trailing data, not necessarily incl_len's worth
            let mut d = PcapStreamDecoder::new(2048);
            let _ = d.push(&b);
        }
    }
    #[test]
    fn never_panics_on_malformed_extended_fields() {
        // ifindex/protocol/pkt_type/pad have no validity constraint — any
        // bit pattern must decode without panicking.
        for (ifindex, protocol, pkt_type, pad) in [
            (0u32, 0u16, 0u8, 0u8),
            (u32::MAX, u16::MAX, u8::MAX, u8::MAX),
            (0xDEAD_BEEF, 0xBEEF, 0x7F, 0x01),
        ] {
            let mut b = extended_global_header_le(2048, LINKTYPE_ETHERNET);
            b.extend(extended_record_le(
                ifindex, protocol, pkt_type, pad, &ARP_FRAME,
            ));
            let packets = PcapStreamDecoder::new(2048).push(&b).unwrap();
            assert_eq!(
                packets[0].extended_meta,
                Some(ExtendedRecordMeta {
                    ifindex,
                    protocol,
                    pkt_type,
                    pad,
                })
            );
        }
    }
    #[test]
    fn never_panics_across_many_tiny_repeated_feeds() {
        let mut b = extended_global_header_le(2048, LINKTYPE_ETHERNET);
        for i in 0..30u32 {
            b.extend(extended_record_le(i, 1, 0, 0, &ARP_FRAME));
        }
        b.extend(vec![0xEE; 7]); // trailing partial record, never completed
        let mut rng = Xorshift(0xA24BAED4963EE407);
        let mut d = PcapStreamDecoder::new(2048);
        let mut total = 0;
        let mut i = 0;
        while i < b.len() {
            let step = 1 + (rng.next() % 5) as usize;
            let end = (i + step).min(b.len());
            total += d.push(&b[i..end]).unwrap().len();
            i = end;
        }
        assert_eq!(total, 30);
        // Trailing partial record: finish() must report it, not panic.
        assert_eq!(d.finish(), Err(PcapError::TruncatedRecord));
    }
}
