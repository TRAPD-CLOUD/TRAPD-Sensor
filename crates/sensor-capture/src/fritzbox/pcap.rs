use thiserror::Error;

const GLOBAL: usize = 24;
const RECORD: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}
#[derive(Debug, PartialEq, Eq)]
pub struct PcapPacket {
    pub timestamp_seconds: u32,
    pub timestamp_fraction: u32,
    pub original_len: u32,
    pub data: Vec<u8>,
}
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PcapError {
    #[error("invalid PCAP global header")]
    InvalidHeader,
    #[error("PCAP snapshot length exceeds configured bound")]
    SnapshotTooLarge,
    #[error("PCAP record length is invalid or exceeds configured bound")]
    InvalidPacketLength,
    #[error("PCAP stream ended in a partial header or record")]
    Truncated,
    #[error("PCAP receive buffer limit exceeded")]
    BufferLimit,
}

/// Incremental classic-PCAP decoder. `push` accepts arbitrary transport
/// fragmentation. The allocation is capped at global-header + record-header +
/// one maximum packet; consumed prefixes are drained before accepting bytes.
pub struct PcapStreamDecoder {
    buffer: Vec<u8>,
    endian: Option<Endianness>,
    max_packet: usize,
    snaplen: u32,
    link_type: Option<u32>,
}
impl PcapStreamDecoder {
    pub fn new(max_packet: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(max_packet.min(65536) + RECORD),
            endian: None,
            max_packet,
            snaplen: 0,
            link_type: None,
        }
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<PcapPacket>, PcapError> {
        let limit = self
            .max_packet
            .checked_add(GLOBAL + RECORD)
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
            self.endian = Some(match self.buffer[0..4] {
                [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => Endianness::Little,
                [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => Endianness::Big,
                _ => return Err(PcapError::InvalidHeader),
            });
            let e = self.endian.unwrap();
            if read16(&self.buffer[4..6], e) != 2 {
                return Err(PcapError::InvalidHeader);
            }
            self.snaplen = read32(&self.buffer[16..20], e);
            if self.snaplen == 0 || self.snaplen as usize > self.max_packet {
                return Err(PcapError::SnapshotTooLarge);
            }
            self.link_type = Some(read32(&self.buffer[20..24], e));
            self.buffer.drain(..GLOBAL);
        }
        loop {
            if self.buffer.len() < RECORD {
                break;
            }
            let e = self.endian.unwrap();
            let cap = read32(&self.buffer[8..12], e);
            let original = read32(&self.buffer[12..16], e);
            if cap == 0 || cap > self.snaplen || cap as usize > self.max_packet || cap > original {
                return Err(PcapError::InvalidPacketLength);
            }
            let total = RECORD + cap as usize;
            if self.buffer.len() < total {
                break;
            }
            packets.push(PcapPacket {
                timestamp_seconds: read32(&self.buffer[0..4], e),
                timestamp_fraction: read32(&self.buffer[4..8], e),
                original_len: original,
                data: self.buffer[RECORD..total].to_vec(),
            });
            self.buffer.drain(..total);
        }
        Ok(())
    }
    pub fn finish(self) -> Result<(), PcapError> {
        if self.buffer.is_empty() && self.endian.is_some() {
            Ok(())
        } else {
            Err(PcapError::Truncated)
        }
    }
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
    pub fn link_type(&self) -> Option<u32> {
        self.link_type
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
    fn stream() -> Vec<u8> {
        let mut v = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 1, 0, 0, 0,
        ];
        for data in [&b"abc"[..], &b"defg"[..]] {
            v.extend([
                1,
                0,
                0,
                0,
                2,
                0,
                0,
                0,
                data.len() as u8,
                0,
                0,
                0,
                data.len() as u8,
                0,
                0,
                0,
            ]);
            v.extend(data)
        }
        v
    }
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
    fn oversized_snaplen() {
        let mut b = stream();
        b[16] = 65;
        assert_eq!(
            PcapStreamDecoder::new(64).push(&b),
            Err(PcapError::SnapshotTooLarge)
        );
    }
    #[test]
    fn malformed_record_length() {
        let mut b = stream();
        b[32] = 100;
        assert_eq!(
            PcapStreamDecoder::new(64).push(&b),
            Err(PcapError::InvalidPacketLength)
        );
    }
    #[test]
    fn truncated() {
        let b = stream();
        let mut d = PcapStreamDecoder::new(64);
        d.push(&b[..30]).unwrap();
        assert_eq!(d.finish(), Err(PcapError::Truncated));
    }
}
