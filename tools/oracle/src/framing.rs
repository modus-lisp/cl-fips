//! FMP stream reader, from jmcorgan/fips @ 57bc510 src/transport/framing.rs.
//!
//! Lines 13-94 (constants, `StreamError`, its `Display` and `From`) are copied
//! verbatim.  `read_fmp_packet` (lines 112-185) is TRANSLITERATED from
//! tokio's `AsyncRead` to `std::io::Read`: the body is upstream's statement for
//! statement with `.await` removed.  Upstream's async version cannot be used
//! here without tokio, which the oracle does not otherwise need.
#![allow(dead_code)]

use crate::fmp_wire as wire;
use crate::noise::TAG_SIZE;
use std::io::Read;

/// FMP phase values (low nibble of byte 0).
const PHASE_ESTABLISHED: u8 = wire::PHASE_ESTABLISHED;
const PHASE_MSG1: u8 = wire::PHASE_MSG1;
const PHASE_MSG2: u8 = wire::PHASE_MSG2;

/// Size of the FMP common prefix.
const PREFIX_SIZE: usize = wire::COMMON_PREFIX_SIZE;

/// Overhead for established frames: the header bytes left after the prefix,
/// then payload_len bytes of ciphertext, then the AEAD tag.
const ESTABLISHED_REMAINING_HEADER: usize = wire::ESTABLISHED_HEADER_SIZE - PREFIX_SIZE;
const AEAD_TAG_SIZE: usize = TAG_SIZE;

/// Errors from the FMP stream reader.
#[derive(Debug)]
pub enum StreamError {
    /// Unknown FMP version — not a FIPS connection (e.g., TLS ClientHello).
    UnknownVersion(u8),
    /// Unknown FMP phase byte — protocol error, close connection.
    UnknownPhase(u8),
    /// Payload length exceeds the connection's MTU — corrupted or malicious.
    PayloadTooLarge {
        payload_len: u16,
        max_payload_len: u16,
    },
    /// Handshake packet has unexpected payload_len for its phase.
    HandshakeSizeMismatch { phase: u8, expected: u16, got: u16 },
    /// I/O error (including EOF).
    Io(std::io::Error),
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::UnknownVersion(v) => write!(f, "unknown FMP version: {}", v),
            StreamError::UnknownPhase(p) => write!(f, "unknown FMP phase: 0x{:02x}", p),
            StreamError::PayloadTooLarge {
                payload_len,
                max_payload_len,
            } => {
                write!(
                    f,
                    "payload_len {} exceeds max {}",
                    payload_len, max_payload_len
                )
            }
            StreamError::HandshakeSizeMismatch {
                phase,
                expected,
                got,
            } => {
                write!(
                    f,
                    "handshake phase 0x{:x}: expected payload_len {}, got {}",
                    phase, expected, got
                )
            }
            StreamError::Io(e) => write!(f, "io: {}", e),
        }
    }
}

impl std::error::Error for StreamError {}

impl From<std::io::Error> for StreamError {
    fn from(e: std::io::Error) -> Self {
        StreamError::Io(e)
    }
}

/// Known wire sizes for handshake messages.
/// msg1: 4 (prefix) + 4 (sender_idx) + 106 (noise_msg1) = 114 bytes
/// msg2: 4 (prefix) + 4 (sender_idx) + 4 (receiver_idx) + 57 (noise_msg2) = 69 bytes
const MSG1_WIRE_SIZE: usize = wire::MSG1_WIRE_SIZE;
const MSG2_WIRE_SIZE: usize = wire::MSG2_WIRE_SIZE;

/// Expected payload_len for msg1: sender_idx(4) + noise_msg1(106) = 110.
const MSG1_PAYLOAD_LEN: u16 = (MSG1_WIRE_SIZE - PREFIX_SIZE) as u16;

/// Expected payload_len for msg2: sender_idx(4) + receiver_idx(4) + noise_msg2(57) = 65.
const MSG2_PAYLOAD_LEN: u16 = (MSG2_WIRE_SIZE - PREFIX_SIZE) as u16;

/// `read_fmp_packet`, transliterated to blocking `std::io::Read`.
pub fn read_fmp_packet<R: Read>(reader: &mut R, mtu: u16) -> Result<Vec<u8>, StreamError> {
    // Read the 4-byte FMP common prefix
    let mut prefix = [0u8; PREFIX_SIZE];
    reader.read_exact(&mut prefix)?;

    let version = prefix[0] >> 4;
    let phase = prefix[0] & 0x0F;

    if version != wire::FMP_VERSION {
        return Err(StreamError::UnknownVersion(version));
    }

    let payload_len = u16::from_le_bytes([prefix[2], prefix[3]]);

    // Compute remaining bytes based on phase
    let remaining = match phase {
        PHASE_ESTABLISHED => {
            // Validate payload_len against MTU:
            // total packet = 16 (header) + payload_len + 16 (tag) = payload_len + 32
            // max_payload_len = mtu - 32
            let max_payload_len = mtu.saturating_sub(
                (ESTABLISHED_REMAINING_HEADER + PREFIX_SIZE + AEAD_TAG_SIZE) as u16,
            );
            if payload_len > max_payload_len {
                return Err(StreamError::PayloadTooLarge {
                    payload_len,
                    max_payload_len,
                });
            }
            // remaining = 12 (rest of header) + payload_len + 16 (AEAD tag)
            ESTABLISHED_REMAINING_HEADER + payload_len as usize + AEAD_TAG_SIZE
        }
        PHASE_MSG1 => {
            if payload_len != MSG1_PAYLOAD_LEN {
                return Err(StreamError::HandshakeSizeMismatch {
                    phase,
                    expected: MSG1_PAYLOAD_LEN,
                    got: payload_len,
                });
            }
            payload_len as usize
        }
        PHASE_MSG2 => {
            if payload_len != MSG2_PAYLOAD_LEN {
                return Err(StreamError::HandshakeSizeMismatch {
                    phase,
                    expected: MSG2_PAYLOAD_LEN,
                    got: payload_len,
                });
            }
            payload_len as usize
        }
        _ => {
            return Err(StreamError::UnknownPhase(phase));
        }
    };

    // Allocate buffer for the complete packet (prefix + remaining)
    let total = PREFIX_SIZE + remaining;
    let mut packet = vec![0u8; total];
    packet[..PREFIX_SIZE].copy_from_slice(&prefix);
    reader.read_exact(&mut packet[PREFIX_SIZE..])?;

    Ok(packet)
}
