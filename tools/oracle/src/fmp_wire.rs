//! FMP established-frame wire codec, copied VERBATIM from jmcorgan/fips @
//! 57bc510, src/proto/fmp/wire.rs: lines 191-392 (constants, CommonPrefix,
//! EncryptedHeader), 393-547 (Msg1Header, Msg2Header, build_msg1,
//! build_msg2 -- the packets a link rekey travels in) and 548-605
//! (build_established_header, build_encrypted, prepend_inner_header,
//! strip_inner_header).  Only the imports and the
//! minimal `SessionIndex` stand-in below are not upstream text (upstream's is
//! src/utils/index.rs, a u32 newtype with the same LE byte conversions); the
//! handshake/Disconnect halves of that file are not needed and not copied.
#![allow(dead_code)]

use crate::noise::{HANDSHAKE_MSG1_SIZE, HANDSHAKE_MSG2_SIZE, TAG_SIZE};

/// Stand-in for upstream `utils::index::SessionIndex` (a `u32` newtype).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionIndex(u32);

impl SessionIndex {
    pub fn new(v: u32) -> Self {
        Self(v)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn to_le_bytes(&self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
    pub fn from_le_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_le_bytes(bytes))
    }
}

// ============================================================================
// Constants
// ============================================================================

/// FMP protocol version (4 high bits of byte 0).
pub const FMP_VERSION: u8 = 0;

/// Phase value for established (encrypted) frames.
pub const PHASE_ESTABLISHED: u8 = 0x0;

/// Phase value for Noise IK message 1 (handshake initiation).
pub const PHASE_MSG1: u8 = 0x1;

/// Phase value for Noise IK message 2 (handshake response).
pub const PHASE_MSG2: u8 = 0x2;

/// Size of the common packet prefix (all packet types).
pub const COMMON_PREFIX_SIZE: usize = 4;

/// Size of the full established frame header (prefix + receiver_idx + counter).
pub const ESTABLISHED_HEADER_SIZE: usize = 16;

/// Size of Noise IK message 1 wire packet: prefix + sender_idx + noise_msg1.
pub const MSG1_WIRE_SIZE: usize = COMMON_PREFIX_SIZE + 4 + HANDSHAKE_MSG1_SIZE; // 114 bytes

/// Size of Noise IK message 2 wire packet: prefix + sender_idx + receiver_idx + noise_msg2.
pub const MSG2_WIRE_SIZE: usize = COMMON_PREFIX_SIZE + 4 + 4 + HANDSHAKE_MSG2_SIZE; // 69 bytes

/// Minimum size for encrypted frame: header + tag (no plaintext).
pub const ENCRYPTED_MIN_SIZE: usize = ESTABLISHED_HEADER_SIZE + TAG_SIZE; // 32 bytes

/// Size of the encrypted inner header (timestamp + message type).
pub const INNER_HEADER_SIZE: usize = 5;

// Flag bit constants (byte 1 of common prefix, meaningful only for phase 0x0).
// Reserved for upcoming rekeying, congestion signaling, and RTT measurement.
#[allow(dead_code)]
/// Key epoch flag — selects active key during rekeying.
pub const FLAG_KEY_EPOCH: u8 = 0x01;
#[allow(dead_code)]
/// Congestion Experienced echo flag.
pub const FLAG_CE: u8 = 0x02;
#[allow(dead_code)]
/// Spin bit for RTT measurement.
pub const FLAG_SP: u8 = 0x04;

// ============================================================================
// Wire Length Validation
// ============================================================================

/// Expected `payload_len` for a packet of `phase` and total wire length
/// `total`, or `None` if the phase carries no fixed relationship.
///
/// Each frame kind states its own relationship; there is no single shared
/// convention. The handshake frames count everything after the 4-byte common
/// prefix. The established frame counts only the inner plaintext, excluding
/// both the 16-byte header and the AEAD tag, which is what
/// [`CommonPrefix::payload_len`] documents.
///
/// The handshake arms are built from the same constants the encoders use; the
/// established arm is not, since no encoder reads `ENCRYPTED_MIN_SIZE`. Neither
/// shape stops a one-sided edit from making the two disagree, which is what the
/// tests below exist to catch.
///
/// A `None` from the established arm means "no fixed relationship", so a caller
/// skips such a frame rather than rejecting it. That is the safe direction: a
/// truncating cast here would produce a false rejection instead.
pub fn expected_payload_len(phase: u8, total: usize) -> Option<u16> {
    match phase {
        PHASE_MSG1 => Some((MSG1_WIRE_SIZE - COMMON_PREFIX_SIZE) as u16),
        PHASE_MSG2 => Some((MSG2_WIRE_SIZE - COMMON_PREFIX_SIZE) as u16),
        PHASE_ESTABLISHED => total
            .checked_sub(ENCRYPTED_MIN_SIZE)
            .and_then(|n| u16::try_from(n).ok()),
        _ => None,
    }
}

// ============================================================================
// Common Prefix
// ============================================================================

/// Parsed common packet prefix (first 4 bytes of every FMP packet).
///
/// Wire format:
/// ```text
/// [ver(4bits)+phase(4bits)][flags:1][payload_len:2 LE]
/// ```
#[derive(Clone, Debug)]
pub struct CommonPrefix {
    /// Protocol version (high nibble of byte 0).
    pub version: u8,
    /// Session lifecycle phase (low nibble of byte 0).
    pub phase: u8,
    /// Per-packet signal flags (meaningful only for phase 0x0).
    #[allow(dead_code)]
    pub flags: u8,
    /// Length of payload following the phase-specific header (excludes AEAD tag).
    #[allow(dead_code)]
    pub payload_len: u16,
}

impl CommonPrefix {
    /// Parse a common prefix from the first 4 bytes of packet data.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < COMMON_PREFIX_SIZE {
            return None;
        }

        let version = data[0] >> 4;
        let phase = data[0] & 0x0F;
        let flags = data[1];
        let payload_len = u16::from_le_bytes([data[2], data[3]]);

        Some(Self {
            version,
            phase,
            flags,
            payload_len,
        })
    }

    /// Encode the ver+phase byte.
    fn ver_phase_byte(version: u8, phase: u8) -> u8 {
        (version << 4) | (phase & 0x0F)
    }
}

// ============================================================================
// Encrypted Frame Header
// ============================================================================

/// Parsed established frame header (phase 0x0).
///
/// Wire format (16 bytes):
/// ```text
/// [ver+phase:1][flags:1][payload_len:2 LE][receiver_idx:4 LE][counter:8 LE]
/// ```
///
/// The full 16-byte header is used as AAD for the AEAD construction.
#[derive(Clone, Debug)]
pub struct EncryptedHeader {
    /// Per-packet flags (K, CE, SP).
    #[allow(dead_code)]
    pub flags: u8,
    /// Length of encrypted payload (excluding AEAD tag).
    #[allow(dead_code)]
    pub payload_len: u16,
    /// Session index chosen by the receiver (for O(1) lookup).
    pub receiver_idx: SessionIndex,
    /// Monotonic counter used as AEAD nonce.
    pub counter: u64,
    /// Raw 16-byte header for use as AEAD AAD.
    pub header_bytes: [u8; ESTABLISHED_HEADER_SIZE],
}

impl EncryptedHeader {
    /// Parse an established frame header from packet data.
    ///
    /// Returns None if the packet is too short or has wrong version/phase.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < ENCRYPTED_MIN_SIZE {
            return None;
        }

        let version = data[0] >> 4;
        let phase = data[0] & 0x0F;

        if version != FMP_VERSION || phase != PHASE_ESTABLISHED {
            return None;
        }

        let flags = data[1];
        let payload_len = u16::from_le_bytes([data[2], data[3]]);
        let receiver_idx = SessionIndex::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let counter = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);

        let mut header_bytes = [0u8; ESTABLISHED_HEADER_SIZE];
        header_bytes.copy_from_slice(&data[..ESTABLISHED_HEADER_SIZE]);

        Some(Self {
            flags,
            payload_len,
            receiver_idx,
            counter,
            header_bytes,
        })
    }

    /// Offset where ciphertext begins in the original packet.
    pub fn ciphertext_offset(&self) -> usize {
        ESTABLISHED_HEADER_SIZE
    }

    /// Get the ciphertext slice from the original packet.
    #[cfg(test)]
    pub fn ciphertext<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[ESTABLISHED_HEADER_SIZE..]
    }
}

/// Build the 16-byte outer header for an established frame.
///
/// Returns the header bytes (for use as AAD) separately from the construction.
pub fn build_established_header(
    receiver_idx: SessionIndex,
    counter: u64,
    flags: u8,
    payload_len: u16,
) -> [u8; ESTABLISHED_HEADER_SIZE] {
    let mut header = [0u8; ESTABLISHED_HEADER_SIZE];
    header[0] = CommonPrefix::ver_phase_byte(FMP_VERSION, PHASE_ESTABLISHED);
    header[1] = flags;
    header[2..4].copy_from_slice(&payload_len.to_le_bytes());
    header[4..8].copy_from_slice(&receiver_idx.to_le_bytes());
    header[8..16].copy_from_slice(&counter.to_le_bytes());
    header
}

/// Build a wire-format encrypted frame.
///
/// Format: `[header:16][ciphertext+tag]`
///
/// The header is constructed from the parameters and used as AAD during
/// encryption. The caller should use `build_established_header` to construct
/// the header, encrypt with it as AAD, then call this to assemble the packet.
pub fn build_encrypted(header: &[u8; ESTABLISHED_HEADER_SIZE], ciphertext: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + ciphertext.len());
    packet.extend_from_slice(header);
    packet.extend_from_slice(ciphertext);
    packet
}

// ============================================================================
// Inner Header Helpers
// ============================================================================

/// Prepend the 5-byte inner header (timestamp + msg_type) to a link message.
///
/// The caller provides the original plaintext starting with `[msg_type][payload...]`.
/// This prepends `[timestamp:4 LE]` before the msg_type byte.
pub fn prepend_inner_header(timestamp_ms: u32, plaintext: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + plaintext.len());
    buf.extend_from_slice(&timestamp_ms.to_le_bytes());
    buf.extend_from_slice(plaintext);
    buf
}

/// Strip the 4-byte timestamp from a decrypted inner payload.
///
/// Returns `(timestamp, &payload_starting_at_msg_type)` or None if too short.
pub fn strip_inner_header(plaintext: &[u8]) -> Option<(u32, &[u8])> {
    if plaintext.len() < INNER_HEADER_SIZE {
        return None;
    }
    let timestamp = u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
    Some((timestamp, &plaintext[4..]))
}

// ============================================================================
// Msg1 Header
// ============================================================================

/// Parsed Noise IK message 1 header (phase 0x1).
///
/// Wire format (114 bytes):
/// ```text
/// [0x01][0x00][payload_len:2 LE][sender_idx:4 LE][noise_msg1:106]
/// ```
#[derive(Clone, Debug)]
pub struct Msg1Header {
    /// Session index chosen by the sender (becomes receiver_idx for responses).
    pub sender_idx: SessionIndex,
    /// Offset where Noise msg1 payload begins.
    pub noise_msg1_offset: usize,
}

impl Msg1Header {
    /// Parse a msg1 header from packet data.
    ///
    /// Returns None if the packet has wrong size or version/phase.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != MSG1_WIRE_SIZE {
            return None;
        }

        let version = data[0] >> 4;
        let phase = data[0] & 0x0F;

        if version != FMP_VERSION || phase != PHASE_MSG1 {
            return None;
        }

        // flags must be zero during handshake
        if data[1] != 0 {
            return None;
        }

        let sender_idx = SessionIndex::from_le_bytes([data[4], data[5], data[6], data[7]]);

        Some(Self {
            sender_idx,
            noise_msg1_offset: COMMON_PREFIX_SIZE + 4, // 8
        })
    }

    /// Get the Noise msg1 payload from the original packet.
    #[cfg(test)]
    pub fn noise_msg1<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.noise_msg1_offset..]
    }
}

// ============================================================================
// Msg2 Header
// ============================================================================

/// Parsed Noise IK message 2 header (phase 0x2).
///
/// Wire format (69 bytes):
/// ```text
/// [0x02][0x00][payload_len:2 LE][sender_idx:4 LE][receiver_idx:4 LE][noise_msg2:57]
/// ```
#[derive(Clone, Debug)]
pub struct Msg2Header {
    /// Session index chosen by the responder.
    pub sender_idx: SessionIndex,
    /// Echo of the initiator's sender_idx from msg1.
    pub receiver_idx: SessionIndex,
    /// Offset where Noise msg2 payload begins.
    pub noise_msg2_offset: usize,
}

impl Msg2Header {
    /// Parse a msg2 header from packet data.
    ///
    /// Returns None if the packet has wrong size or version/phase.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != MSG2_WIRE_SIZE {
            return None;
        }

        let version = data[0] >> 4;
        let phase = data[0] & 0x0F;

        if version != FMP_VERSION || phase != PHASE_MSG2 {
            return None;
        }

        // flags must be zero during handshake
        if data[1] != 0 {
            return None;
        }

        let sender_idx = SessionIndex::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let receiver_idx = SessionIndex::from_le_bytes([data[8], data[9], data[10], data[11]]);

        Some(Self {
            sender_idx,
            receiver_idx,
            noise_msg2_offset: COMMON_PREFIX_SIZE + 4 + 4, // 12
        })
    }

    /// Get the Noise msg2 payload from the original packet.
    #[cfg(test)]
    pub fn noise_msg2<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.noise_msg2_offset..]
    }
}

// ============================================================================
// Serialization Helpers
// ============================================================================

/// Build a wire-format msg1 packet.
///
/// Format: `[0x01][0x00][payload_len:2 LE][sender_idx:4 LE][noise_msg1:106]`
pub fn build_msg1(sender_idx: SessionIndex, noise_msg1: &[u8]) -> Vec<u8> {
    debug_assert_eq!(noise_msg1.len(), HANDSHAKE_MSG1_SIZE);

    let payload_len = (4 + noise_msg1.len()) as u16; // sender_idx + noise_msg1

    let mut packet = Vec::with_capacity(MSG1_WIRE_SIZE);
    packet.push(CommonPrefix::ver_phase_byte(FMP_VERSION, PHASE_MSG1));
    packet.push(0x00); // flags must be zero
    packet.extend_from_slice(&payload_len.to_le_bytes());
    packet.extend_from_slice(&sender_idx.to_le_bytes());
    packet.extend_from_slice(noise_msg1);
    packet
}

/// Build a wire-format msg2 packet.
///
/// Format: `[0x02][0x00][payload_len:2 LE][sender_idx:4 LE][receiver_idx:4 LE][noise_msg2:57]`
pub fn build_msg2(
    sender_idx: SessionIndex,
    receiver_idx: SessionIndex,
    noise_msg2: &[u8],
) -> Vec<u8> {
    debug_assert_eq!(noise_msg2.len(), HANDSHAKE_MSG2_SIZE);

    let payload_len = (4 + 4 + noise_msg2.len()) as u16; // sender + receiver + noise

    let mut packet = Vec::with_capacity(MSG2_WIRE_SIZE);
    packet.push(CommonPrefix::ver_phase_byte(FMP_VERSION, PHASE_MSG2));
    packet.push(0x00); // flags must be zero
    packet.extend_from_slice(&payload_len.to_le_bytes());
    packet.extend_from_slice(&sender_idx.to_le_bytes());
    packet.extend_from_slice(&receiver_idx.to_le_bytes());
    packet.extend_from_slice(noise_msg2);
    packet
}
