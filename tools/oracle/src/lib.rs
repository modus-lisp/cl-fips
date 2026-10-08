//! FIPS Noise oracle: the upstream Noise module, unmodified, plus the FMP
//! established-frame codec copied from upstream src/proto/fmp/wire.rs and the
//! stream reader from src/transport/framing.rs.
pub mod fmp_wire;
pub mod framing;
pub mod noise;
