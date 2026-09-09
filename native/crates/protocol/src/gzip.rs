#![forbid(unsafe_code)]

//! Bounded RFC 1951/1952 decoding into a private consumer. No I/O or extraction.
use crate::patch_capture::CaptureError as Error;

const HISTORY: usize = 32_768;
const CHUNK: usize = 8192;
const MAX_MEMBERS: usize = 64;
const MAX_HEADER: usize = 128 * 1024;
const MAX_HEADER_TEXT: usize = 4096;

const fn crc_table() -> [u32; 256] {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        let mut value = i as u32;
        let mut bit = 0;
        while bit < 8 {
            value = (value >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(value & 1));
            bit += 1;
        }
        table[i] = value;
        i += 1;
    }
    table
}
const CRC: [u32; 256] = crc_table();
fn crc_byte(crc: u32, byte: u8) -> u32 {
    (crc >> 8) ^ CRC[((crc ^ u32::from(byte)) & 255) as usize]
}
fn crc32(bytes: &[u8]) -> u32 {
    !bytes
        .iter()
        .fold(u32::MAX, |crc, byte| crc_byte(crc, *byte))
}

struct Bits<'a> {
    input: &'a [u8],
    byte: usize,
    bit: u8,
}
impl<'a> Bits<'a> {
    fn read(&mut self, count: u8) -> Result<u32, Error> {
        let mut value = 0;
        for shift in 0..count {
            let byte = *self.input.get(self.byte).ok_or(Error::Malformed)?;
            value |= u32::from((byte >> self.bit) & 1) << shift;
            self.bit += 1;
            if self.bit == 8 {
                self.bit = 0;
                self.byte += 1;
            }
        }
        Ok(value)
    }
    fn align(&mut self) {
        if self.bit != 0 {
            self.byte += 1;
            self.bit = 0;
        }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        if self.bit != 0 {
            return Err(Error::Malformed);
        }
        let end = self.byte.checked_add(count).ok_or(Error::Limit)?;
        let bytes = self.input.get(self.byte..end).ok_or(Error::Malformed)?;
        self.byte = end;
        Ok(bytes)
    }
    fn text(&mut self) -> Result<(), Error> {
        for _ in 0..=MAX_HEADER_TEXT {
            if self.take(1)?[0] == 0 {
                return Ok(());
            }
        }
        Err(Error::Limit)
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Alphabet {
    Lengths,
    Literals,
    Distances,
}
struct Huffman {
    counts: [u16; 16],
    first_codes: [u16; 16],
    offsets: [u16; 16],
    symbols: [u16; 288],
    maximum: usize,
}
impl Huffman {
    fn new(lengths: &[u8], alphabet: Alphabet) -> Result<Self, Error> {
        if lengths.len() > 288 {
            return Err(Error::Malformed);
        }
        let mut tree = Self {
            counts: [0; 16],
            first_codes: [0; 16],
            offsets: [0; 16],
            symbols: [0; 288],
            maximum: 0,
        };
        for length in lengths {
            if *length > 15 {
                return Err(Error::Malformed);
            }
            if *length != 0 {
                tree.counts[*length as usize] += 1;
                tree.maximum = tree.maximum.max(*length as usize);
            }
        }
        if tree.maximum == 0 {
            return if alphabet == Alphabet::Distances {
                Ok(tree)
            } else {
                Err(Error::Malformed)
            };
        }
        let mut slots: i32 = 1;
        let mut code = 0u16;
        let mut offset = 0u16;
        for length in 1..=15 {
            slots = (slots << 1) - i32::from(tree.counts[length]);
            if slots < 0 {
                return Err(Error::Malformed);
            }
            code = (code + tree.counts[length - 1]) << 1;
            tree.first_codes[length] = code;
            tree.offsets[length] = offset;
            offset += tree.counts[length];
        }
        // Incomplete code-length trees are invalid. A one-symbol, one-bit literal
        // or distance tree is permitted; an unused empty distance tree is handled above.
        if slots != 0 && (alphabet == Alphabet::Lengths || tree.maximum != 1) {
            return Err(Error::Malformed);
        }
        let mut next = tree.offsets;
        for (symbol, length) in lengths.iter().enumerate() {
            if *length != 0 {
                let index = next[*length as usize] as usize;
                tree.symbols[index] = symbol as u16;
                next[*length as usize] += 1;
            }
        }
        Ok(tree)
    }
    fn decode(&self, bits: &mut Bits<'_>) -> Result<u16, Error> {
        let mut code = 0u16;
        for length in 1..=self.maximum {
            code = (code << 1) | bits.read(1)? as u16;
            if code >= self.first_codes[length] {
                let index = code - self.first_codes[length];
                if index < self.counts[length] {
                    return Ok(self.symbols[(self.offsets[length] + index) as usize]);
                }
            }
        }
        Err(Error::Malformed)
    }
}

struct Output<F> {
    consume: F,
    history: [u8; HISTORY],
    pending: [u8; CHUNK],
    pending_len: usize,
    total: usize,
    member_bytes: usize,
    maximum: usize,
    crc: u32,
}
impl<F: FnMut(&[u8]) -> Result<(), Error>> Output<F> {
    fn flush(&mut self) -> Result<(), Error> {
        if self.pending_len != 0 {
            (self.consume)(&self.pending[..self.pending_len])?;
            self.pending_len = 0;
        }
        Ok(())
    }
    fn emit(&mut self, byte: u8) -> Result<(), Error> {
        if self.total >= self.maximum {
            return Err(Error::Limit);
        }
        self.history[self.member_bytes % HISTORY] = byte;
        self.member_bytes += 1;
        self.total += 1;
        self.crc = crc_byte(self.crc, byte);
        self.pending[self.pending_len] = byte;
        self.pending_len += 1;
        if self.pending_len == CHUNK {
            self.flush()?;
        }
        Ok(())
    }
    fn copy(&mut self, distance: usize, length: usize) -> Result<(), Error> {
        if distance == 0 || distance > HISTORY || distance > self.member_bytes {
            return Err(Error::Malformed);
        }
        if length > self.maximum - self.total {
            return Err(Error::Limit);
        }
        for _ in 0..length {
            // Read after each emitted byte: overlapping back-references are legal.
            let byte = self.history[(self.member_bytes - distance) % HISTORY];
            self.emit(byte)?;
        }
        Ok(())
    }
}

fn dynamic_trees(bits: &mut Bits<'_>) -> Result<(Huffman, Huffman), Error> {
    let literals = bits.read(5)? as usize + 257;
    let distances = bits.read(5)? as usize + 1;
    let code_count = bits.read(4)? as usize + 4;
    if literals > 286 {
        return Err(Error::Malformed);
    }
    const ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let mut code_lengths = [0u8; 19];
    for index in ORDER.iter().take(code_count) {
        code_lengths[*index] = bits.read(3)? as u8;
    }
    let codes = Huffman::new(&code_lengths, Alphabet::Lengths)?;
    let mut lengths = [0u8; 318];
    let count = literals + distances;
    let mut at = 0;
    while at < count {
        let code = codes.decode(bits)?;
        let (value, repeat) = match code {
            0..=15 => (code as u8, 1),
            16 if at != 0 => (lengths[at - 1], bits.read(2)? as usize + 3),
            17 => (0, bits.read(3)? as usize + 3),
            18 => (0, bits.read(7)? as usize + 11),
            _ => return Err(Error::Malformed),
        };
        if repeat > count - at {
            return Err(Error::Malformed);
        }
        lengths[at..at + repeat].fill(value);
        at += repeat;
    }
    if lengths[256] == 0 {
        return Err(Error::Malformed);
    }
    Ok((
        Huffman::new(&lengths[..literals], Alphabet::Literals)?,
        Huffman::new(&lengths[literals..count], Alphabet::Distances)?,
    ))
}

fn inflate<F: FnMut(&[u8]) -> Result<(), Error>>(
    bits: &mut Bits<'_>,
    output: &mut Output<F>,
) -> Result<(), Error> {
    const LENGTH_BASE: [usize; 29] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
        131, 163, 195, 227, 258,
    ];
    const LENGTH_EXTRA: [u8; 29] = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    ];
    const DISTANCE_BASE: [usize; 30] = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
        2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
    ];
    const DISTANCE_EXTRA: [u8; 30] = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
        13, 13,
    ];
    loop {
        let last = bits.read(1)? != 0;
        match bits.read(2)? {
            0 => {
                bits.align();
                let length = bits.read(16)? as u16;
                if bits.read(16)? as u16 != !length {
                    return Err(Error::Malformed);
                }
                if usize::from(length) > output.maximum - output.total {
                    return Err(Error::Limit);
                }
                for byte in bits.take(usize::from(length))? {
                    output.emit(*byte)?;
                }
            }
            kind @ (1 | 2) => {
                let (literals, distances) = if kind == 1 {
                    let mut lengths = [8u8; 288];
                    lengths[144..256].fill(9);
                    lengths[256..280].fill(7);
                    (
                        Huffman::new(&lengths, Alphabet::Literals)?,
                        Huffman::new(&[5; 32], Alphabet::Distances)?,
                    )
                } else {
                    dynamic_trees(bits)?
                };
                loop {
                    match literals.decode(bits)? {
                        byte @ 0..=255 => output.emit(byte as u8)?,
                        256 => break,
                        code @ 257..=285 => {
                            let index = (code - 257) as usize;
                            let length =
                                LENGTH_BASE[index] + bits.read(LENGTH_EXTRA[index])? as usize;
                            let distance_code = distances.decode(bits)? as usize;
                            if distance_code >= 30 {
                                return Err(Error::Malformed);
                            }
                            let distance = DISTANCE_BASE[distance_code]
                                + bits.read(DISTANCE_EXTRA[distance_code])? as usize;
                            output.copy(distance, length)?;
                        }
                        _ => return Err(Error::Malformed),
                    }
                }
            }
            _ => return Err(Error::Malformed),
        }
        if last {
            bits.align();
            return Ok(());
        }
    }
}

/// The consumer is private capture state: emitted chunks are tentative until this
/// function and the consumer's final structural check both succeed.
pub(crate) fn decode<F: FnMut(&[u8]) -> Result<(), Error>>(
    input: &[u8],
    maximum: usize,
    consume: F,
) -> Result<usize, Error> {
    let mut bits = Bits {
        input,
        byte: 0,
        bit: 0,
    };
    let mut output = Output {
        consume,
        history: [0; HISTORY],
        pending: [0; CHUNK],
        pending_len: 0,
        total: 0,
        member_bytes: 0,
        maximum,
        crc: u32::MAX,
    };
    let mut members = 0;
    if input.is_empty() {
        return Err(Error::Malformed);
    }
    while bits.byte < input.len() {
        if members == MAX_MEMBERS {
            return Err(Error::Limit);
        }
        members += 1;
        let start = bits.byte;
        let header = bits.take(10)?;
        if header[..3] != [0x1f, 0x8b, 8] || header[3] & 0xe0 != 0 {
            return Err(Error::Malformed);
        }
        let flags = header[3];
        if flags & 4 != 0 {
            let length = bits.take(2)?;
            let length = u16::from_le_bytes([length[0], length[1]]) as usize;
            bits.take(length)?;
        }
        if flags & 8 != 0 {
            bits.text()?;
        }
        if flags & 16 != 0 {
            bits.text()?;
        }
        if flags & 2 != 0 {
            let checksum = crc32(&input[start..bits.byte]) as u16;
            let expected = bits.take(2)?;
            if checksum != u16::from_le_bytes([expected[0], expected[1]]) {
                return Err(Error::Integrity);
            }
        }
        if bits.byte - start > MAX_HEADER {
            return Err(Error::Limit);
        }
        output.member_bytes = 0;
        output.crc = u32::MAX;
        inflate(&mut bits, &mut output)?;
        let trailer = bits.take(8)?;
        let crc = u32::from_le_bytes(trailer[..4].try_into().map_err(|_| Error::Malformed)?);
        let length = u32::from_le_bytes(trailer[4..].try_into().map_err(|_| Error::Malformed)?);
        if crc != !output.crc || length != output.member_bytes as u32 {
            return Err(Error::Integrity);
        }
        output.flush()?;
    }
    Ok(output.total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_pinned_archives_match_independent_node_zlib_digests() {
        // Expected lengths/SHA-256 were generated with Node's builtin gunzipSync,
        // not this decoder. Hash each output chunk without retaining expanded tar.
        let cases: &[(&[u8], usize, &str)] = &[
            (
                include_bytes!("../../../p2-crypto-crates/block-buffer-0.12.1.crate").as_slice(),
                69632,
                "b9a95f90fe7c4d52a4322a7befa1240b1281d89b2043b3c492cec641ea3e7b59",
            ),
            (
                include_bytes!("../../../p2-crypto-crates/cfg-if-1.0.4.crate").as_slice(),
                38912,
                "e8e3e2bee869c72a8ee215e8b644ed6c9bc40f22827445880fbf5a40bc681075",
            ),
            (
                include_bytes!("../../../p2-crypto-crates/cpufeatures-0.3.0.crate").as_slice(),
                59904,
                "5037002a671e54d42d3cfa48923b1ec736ea74570807b8dea94462762fc0ab33",
            ),
            (
                include_bytes!("../../../p2-crypto-crates/crypto-common-0.2.2.crate").as_slice(),
                62976,
                "85ea742000dff30f20a53b01eb9dd4301039a3589655588d8812500041e57cd4",
            ),
            (
                include_bytes!("../../../p2-crypto-crates/curve25519-dalek-5.0.0.crate").as_slice(),
                1493504,
                "6bdf5aab4f79f4f0fabbb69edcd254a8876f5ece07f21775a2b225c77f6bdd6f",
            ),
            (
                include_bytes!("../../../p2-crypto-crates/curve25519-dalek-derive-0.1.1.crate")
                    .as_slice(),
                49152,
                "a2856c93c2d07c54cc542ea93024c62c8c128821adb092b651381cbfc737155b",
            ),
            (
                include_bytes!("../../../p2-crypto-crates/digest-0.11.3.crate").as_slice(),
                158720,
                "bfae92c1ea404ecd1b69d2168869e37ccc8562acb65193918ee89e46324c06ce",
            ),
            (
                include_bytes!("../../../p2-crypto-crates/ed25519-3.0.0.crate").as_slice(),
                83456,
                "e13a36c495bf105238602a4467189e7027cd857cc8660edcb2b9c9f807b9a7ff",
            ),
            (
                include_bytes!("../../../p2-crypto-crates/ed25519-dalek-3.0.0.crate").as_slice(),
                304128,
                "74a9e55f200ecb5ebf67b248668d608647d77785779a71b5f1077d1797f05943",
            ),
            (
                include_bytes!("../../../p2-crypto-crates/fiat-crypto-0.3.0.crate").as_slice(),
                4722688,
                "716ce0ef44bea20f82bd2c0f87c06da185e6a1360e84a1e5f22a1676fbd92cfa",
            ),
            (
                include_bytes!("../../../p2-crypto-crates/hybrid-array-0.4.14.crate").as_slice(),
                165888,
                "d186a574a19d8141ef87d09d0afb12c939cf34544e2221f1cb408706e8907c64",
            ),
            (
                include_bytes!("../../../p2-crypto-crates/libc-0.2.189.crate").as_slice(),
                4824576,
                "fa1c8f79443998979cbc0c35417abc57133beaa0770f76119fe928185ce0d916",
            ),
            (
                include_bytes!("../../../p2-crypto-crates/proc-macro2-1.0.107.crate").as_slice(),
                297472,
                "cfd8be505b6aa012c4ea2ea0fc54c1159b5482024614bded9d698527163aa541",
            ),
            (
                include_bytes!("../../../p2-crypto-crates/quote-1.0.47.crate").as_slice(),
                165888,
                "22d5993eb0d05811795f0d05b90c9fdadd1089337db59935ce67a39fc47c001c",
            ),
            (
                include_bytes!("../../../p2-crypto-crates/rustc_version-0.4.1.crate").as_slice(),
                56320,
                "0a416d7639ae9c5b4d3863b5f616219e7e6dfc0809c66af475c7d1825cfc5f1c",
            ),
            (
                include_bytes!("../../../p2-crypto-crates/semver-1.0.28.crate").as_slice(),
                150528,
                "58b47d4850ebe9f8ab655973ec98aebe79795f16a2ad5eb4c8bfaae7a5f978d3",
            ),
            (
                include_bytes!("../../../p2-crypto-crates/sha2-0.11.0.crate").as_slice(),
                183296,
                "c00f5cd134af8c59ebc3fee4aa07e1ab9682b9eac62fa23328ca336af02ad63d",
            ),
            (
                include_bytes!("../../../p2-crypto-crates/signature-3.0.0.crate").as_slice(),
                71680,
                "391c5bb6c065b35eaa1be2d25e161f04c3be1448f1044fbd6bb91ab4acb48f9a",
            ),
            (
                include_bytes!("../../../p2-crypto-crates/subtle-2.6.1.crate").as_slice(),
                66048,
                "829bce6f51fd7d19048d6098849458c54f69c2909b0745d25729a7c48cf6d445",
            ),
            (
                include_bytes!("../../../p2-crypto-crates/syn-2.0.119.crate").as_slice(),
                2390528,
                "59a3f642db1713e0a923ae130985cdb3674a592ca39feec0593d08915477d0c3",
            ),
            (
                include_bytes!("../../../p2-crypto-crates/typenum-1.20.1.crate").as_slice(),
                1254400,
                "7af24d2b789cc5a51f7c80070e15281e501d1e5ec10eccf9b4f5884d39218313",
            ),
            (
                include_bytes!("../../../p2-crypto-crates/unicode-ident-1.0.24.crate").as_slice(),
                358912,
                "d6cacd22ffbd8834360851f3c8d1f742f75164ace4b2cd40c90a9ef63d288826",
            ),
        ];
        assert_eq!(cases.len(), 22);
        for (input, length, expected) in cases {
            let mut hash = crate::Sha256State::new();
            let actual = decode(input, *length, |part| {
                hash.update(part);
                Ok(())
            })
            .unwrap();
            assert_eq!(actual, *length);
            let digest: String = hash
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(&digest, expected);
        }
    }
    fn stored(bytes: &[u8]) -> Vec<u8> {
        assert!(bytes.len() <= u16::MAX as usize);
        let size = bytes.len() as u16;
        let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255, 1];
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(!size).to_le_bytes());
        out.extend_from_slice(bytes);
        out.extend_from_slice(&crc32(bytes).to_le_bytes());
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out
    }
    fn decoded(bytes: &[u8], maximum: usize) -> Result<Vec<u8>, Error> {
        let mut result = Vec::new();
        decode(bytes, maximum, |part| {
            result.extend_from_slice(part);
            Ok(())
        })?;
        Ok(result)
    }
    #[test]
    fn stored_crc_truncation_bounds_and_complete_consumption() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        let valid = stored(b"owned input");
        assert_eq!(decoded(&valid, 11).unwrap(), b"owned input");
        assert_eq!(decoded(&valid, 10), Err(Error::Limit));
        for end in 0..valid.len() {
            assert!(decoded(&valid[..end], 100).is_err(), "prefix {end}");
        }
        for index in [2, 3, 11, 12, 13, 14, valid.len() - 8, valid.len() - 4] {
            let mut bad = valid.clone();
            bad[index] ^= 0x80;
            assert!(decoded(&bad, 100).is_err(), "mutation {index}");
        }
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(decoded(&trailing, 100).is_err());
        let mut two = valid.clone();
        two.extend_from_slice(&stored(b"second"));
        assert_eq!(decoded(&two, 17).unwrap(), b"owned inputsecond");
        assert_eq!(decoded(&two, 16), Err(Error::Limit));
    }
    #[test]
    fn optional_header_is_bounded_inert_and_authenticated() {
        let body = stored(b"abc");
        let mut valid = body[..10].to_vec();
        valid[3] = 2 | 4 | 8 | 16;
        valid.extend_from_slice(&[4, 0, b'A', b'B', 0, 0]);
        valid.extend_from_slice(b"../../inert-name\0inert-comment\0");
        valid.extend_from_slice(&(crc32(&valid) as u16).to_le_bytes());
        valid.extend_from_slice(&body[10..]);
        assert_eq!(decoded(&valid, 3).unwrap(), b"abc");
        valid[10] = 5;
        assert!(decoded(&valid, 3).is_err());
        let mut long = body[..10].to_vec();
        long[3] = 8;
        long.extend_from_slice(&[b'a'; MAX_HEADER_TEXT + 1]);
        long.push(0);
        long.extend_from_slice(&body[10..]);
        assert_eq!(decoded(&long, 3), Err(Error::Limit));
        let empty = stored(b"");
        assert_eq!(decoded(&empty.repeat(64), 0).unwrap(), b"");
        assert_eq!(decoded(&empty.repeat(65), 0), Err(Error::Limit));
    }
    #[test]
    fn huffman_and_backreference_malformed_states_refuse() {
        assert!(Huffman::new(&[1, 1, 1], Alphabet::Literals).is_err());
        assert!(Huffman::new(&[2, 2], Alphabet::Literals).is_err());
        assert!(Huffman::new(&[1], Alphabet::Lengths).is_err());
        assert!(Huffman::new(&[16], Alphabet::Literals).is_err());
        assert!(Huffman::new(&[0], Alphabet::Literals).is_err());
        let empty = Huffman::new(&[0], Alphabet::Distances).unwrap();
        assert_eq!(
            empty.decode(&mut Bits {
                input: &[0],
                byte: 0,
                bit: 0
            }),
            Err(Error::Malformed)
        );
        let mut collected = Vec::new();
        let mut output = Output {
            consume: |part: &[u8]| {
                collected.extend_from_slice(part);
                Ok(())
            },
            history: [0; HISTORY],
            pending: [0; CHUNK],
            pending_len: 0,
            total: 0,
            member_bytes: 0,
            maximum: 8,
            crc: u32::MAX,
        };
        assert_eq!(output.copy(1, 3), Err(Error::Malformed));
        output.emit(b'a').unwrap();
        output.copy(1, 7).unwrap();
        assert_eq!(output.copy(1, 1), Err(Error::Limit));
        output.flush().unwrap();
        assert_eq!(collected, b"aaaaaaaa");
        let mut reserved = stored(b"");
        reserved[10] = 7;
        assert_eq!(decoded(&reserved, 10), Err(Error::Malformed));
    }
}
