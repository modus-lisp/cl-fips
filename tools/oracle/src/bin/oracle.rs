//! Emits Noise handshake transcripts from the upstream FIPS Noise module, so the
//! Lisp implementation can be checked byte-for-byte against it.
//!
//!   oracle ik   -- link layer (FMP): Noise_IK_secp256k1_ChaChaPoly_SHA256
//!   oracle xk   -- session layer (FSP): Noise_XK_secp256k1_ChaChaPoly_SHA256
//!
//!   oracle verify-ik-initiator
//!       Upstream plays the IK INITIATOR against a foreign responder, over
//!       stdin/stdout.  stdin line 1: the responder's 33-byte static key (hex).
//!       It prints initiator_static, responder_static, msg1 and `ready=1`, then
//!       reads msg2 (hex) and runs upstream `read_message_2`, printing
//!       `result=ok` (or `result=error` + `error=<text>`), handshake_hash,
//!       remote_epoch, and transport_ciphertext_from_initiator ("hello fips").
//!       Then it reads one more line, a ciphertext from the responder, and
//!       prints its decryption as responder_plaintext (or `responder_result=error`).
//!
//!   oracle verify-ik-responder
//!       Upstream plays the IK RESPONDER against a foreign initiator.  Prints
//!       responder_static and `ready=1`, reads msg1 (hex), runs upstream
//!       `read_message_1` and `write_message_2`, and prints result,
//!       initiator_static (as learned), remote_epoch, msg2, handshake_hash and
//!       transport_ciphertext_from_responder ("hello fips").  Then it reads a
//!       ciphertext from the initiator and prints initiator_plaintext.
//!
//!   oracle verify-xk-initiator
//!       Upstream plays the XK INITIATOR against a foreign responder.  stdin
//!       line 1: the responder's static key.  Prints initiator_static,
//!       responder_static, msg1 and `ready=1`; reads msg2 and runs upstream
//!       `read_xk_message_2` (`result=error` + `error=` on failure), then
//!       `write_xk_message_3`, printing `result=ok`, remote_epoch, msg3,
//!       handshake_hash and transport_ciphertext_from_initiator ("hello
//!       fips").  Then reads a ciphertext from the responder and prints
//!       responder_plaintext (or `responder_result=error`).
//!
//!   oracle verify-xk-responder
//!       Upstream plays the XK RESPONDER against a foreign initiator.  Prints
//!       responder_static and `ready=1`; reads msg1, runs `read_xk_message_1`
//!       and `write_xk_message_2`, printing `msg1_result=ok` (or `=error`)
//!       and msg2.  Reads msg3 and runs `read_xk_message_3`, printing result,
//!       initiator_static (as learned), remote_epoch, handshake_hash and
//!       transport_ciphertext_from_responder ("hello fips").  Then reads a
//!       ciphertext from the initiator and prints initiator_plaintext.
//!
//!   oracle verify-frame
//!       FMP established frames over an IK link.  The handshake is exactly
//!       verify-ik-initiator's (upstream initiator, foreign responder) up to
//!       `result=ok`, handshake_hash and remote_epoch.  It then prints
//!       lisp_receiver_idx and oracle_receiver_idx (decimal) and three frames
//!       built and sealed the way upstream's inline send path does
//!       (node/mod.rs: prepend_inner_header, build_established_header,
//!       encrypt_with_aad with the 16-byte header as AAD, build_encrypted),
//!       addressed to lisp_receiver_idx: frame_N, frame_N_flags,
//!       frame_N_timestamp (decimal) and frame_N_message (msg_type + body),
//!       then `frames_ready=1`.  After that every input line is a frame from
//!       the foreign side: it is parsed with EncryptedHeader::parse, opened
//!       with decrypt_with_replay_check_and_aad (AAD = the header bytes) and
//!       stripped with strip_inner_header, printing frame_receiver_idx,
//!       frame_counter, frame_flags, frame_timestamp, frame_payload_len_ok,
//!       frame_message and finally `frame_result=ok` -- or `error=` and then
//!       `frame_result=error`.  The line `end` (or EOF) stops it.
//!
//!   oracle node-addr
//!       For each input line (a 33-byte compressed key, hex) prints node_addr
//!       (upstream identity/node_addr.rs NodeAddr::from_pubkey over the x-only
//!       key) and address (identity/address.rs FipsAddress::from_node_addr),
//!       both function bodies copied verbatim.  Stops at EOF.
//!
//! Output is one `name=hex` line per field (`result`/`error` lines are text).
//! Keys and ephemerals are random per run, so the output is a transcript to
//! verify against, not a fixed fixture.

use fips_oracle::fmp_wire::{
    EncryptedHeader, ESTABLISHED_HEADER_SIZE, FLAG_CE, FLAG_KEY_EPOCH, FLAG_SP, SessionIndex,
    build_encrypted, build_established_header, prepend_inner_header, strip_inner_header,
};
use fips_oracle::noise::{HandshakeState};
use std::io::{BufRead, Write};
use rand::Rng;
use secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};

fn keypair(secp: &Secp256k1<secp256k1::All>) -> Keypair {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let sk = SecretKey::from_slice(&bytes).expect("valid secret key");
    Keypair::from_secret_key(secp, &sk)
}

fn epoch() -> [u8; 8] {
    let mut e = [0u8; 8];
    rand::rng().fill_bytes(&mut e);
    e
}

fn line(name: &str, bytes: &[u8]) {
    println!("{name}={}", hex::encode(bytes));
}

fn ik(secp: &Secp256k1<secp256k1::All>) {
    let init_kp = keypair(secp);
    let resp_kp = keypair(secp);
    let resp_pub = PublicKey::from_keypair(&resp_kp);
    let mut init = HandshakeState::new_initiator(init_kp, resp_pub);
    let mut resp = HandshakeState::new_responder(resp_kp);
    init.set_local_epoch(epoch());
    resp.set_local_epoch(epoch());

    let msg1 = init.write_message_1().expect("write msg1");
    resp.read_message_1(&msg1).expect("read msg1");
    let msg2 = resp.write_message_2().expect("write msg2");
    init.read_message_2(&msg2).expect("read msg2");

    let h_init = init.handshake_hash();
    let h_resp = resp.handshake_hash();
    assert_eq!(h_init, h_resp, "IK handshake hashes disagree");

    let mut sess = init.into_session().expect("initiator session");
    let ct = sess.encrypt(b"hello fips").expect("encrypt");

    line("pattern", b"IK");
    line("initiator_static", &PublicKey::from_keypair(&init_kp).serialize());
    line("responder_static", &resp_pub.serialize());
    line("msg1", &msg1);
    line("msg2", &msg2);
    line("handshake_hash", &h_init);
    line("transport_plaintext", b"hello fips");
    line("transport_ciphertext_from_initiator", &ct);
}

fn xk(secp: &Secp256k1<secp256k1::All>) {
    let init_kp = keypair(secp);
    let resp_kp = keypair(secp);
    let resp_pub = PublicKey::from_keypair(&resp_kp);
    let mut init = HandshakeState::new_xk_initiator(init_kp, resp_pub);
    let mut resp = HandshakeState::new_xk_responder(resp_kp);
    init.set_local_epoch(epoch());
    resp.set_local_epoch(epoch());

    let msg1 = init.write_xk_message_1().expect("write xk msg1");
    resp.read_xk_message_1(&msg1).expect("read xk msg1");
    let msg2 = resp.write_xk_message_2().expect("write xk msg2");
    init.read_xk_message_2(&msg2).expect("read xk msg2");
    let msg3 = init.write_xk_message_3().expect("write xk msg3");
    resp.read_xk_message_3(&msg3).expect("read xk msg3");

    let h_init = init.handshake_hash();
    let h_resp = resp.handshake_hash();
    assert_eq!(h_init, h_resp, "XK handshake hashes disagree");

    let mut sess = init.into_session().expect("initiator session");
    let ct = sess.encrypt(b"hello fips").expect("encrypt");

    line("pattern", b"XK");
    line("initiator_static", &PublicKey::from_keypair(&init_kp).serialize());
    line("responder_static", &resp_pub.serialize());
    line("msg1", &msg1);
    line("msg2", &msg2);
    line("msg3", &msg3);
    line("handshake_hash", &h_init);
    line("transport_plaintext", b"hello fips");
    line("transport_ciphertext_from_initiator", &ct);
}

/// Read one hex line from stdin; exits if stdin is closed or the hex is bad.
fn read_hex_line() -> Vec<u8> {
    let mut l = String::new();
    if std::io::stdin().lock().read_line(&mut l).unwrap_or(0) == 0 {
        eprintln!("oracle: unexpected end of input");
        std::process::exit(3);
    }
    hex::decode(l.trim()).unwrap_or_else(|e| {
        eprintln!("oracle: bad hex input: {e}");
        std::process::exit(3);
    })
}

fn text(name: &str, value: &str) {
    println!("{name}={value}");
}

fn flush() {
    std::io::stdout().flush().expect("flush stdout");
}

fn verify_ik_initiator(secp: &Secp256k1<secp256k1::All>) {
    let resp_pub = PublicKey::from_slice(&read_hex_line()).unwrap_or_else(|e| {
        eprintln!("oracle: invalid responder static key: {e}");
        std::process::exit(3);
    });
    let init_kp = keypair(secp);
    let mut init = HandshakeState::new_initiator(init_kp, resp_pub);
    init.set_local_epoch(epoch());
    let msg1 = init.write_message_1().expect("write msg1");

    line("initiator_static", &PublicKey::from_keypair(&init_kp).serialize());
    line("responder_static", &resp_pub.serialize());
    line("msg1", &msg1);
    text("ready", "1");
    flush();

    let msg2 = read_hex_line();
    if let Err(e) = init.read_message_2(&msg2) {
        text("result", "error");
        text("error", &e.to_string());
        flush();
        return;
    }
    text("result", "ok");
    line("handshake_hash", &init.handshake_hash());
    line("remote_epoch", &init.remote_epoch().expect("epoch after msg2"));
    let mut sess = init.into_session().expect("initiator session");
    let ct = sess.encrypt(b"hello fips").expect("encrypt");
    line("transport_plaintext", b"hello fips");
    line("transport_ciphertext_from_initiator", &ct);
    flush();

    let ct2 = read_hex_line();
    match sess.decrypt(&ct2) {
        Ok(pt) => line("responder_plaintext", &pt),
        Err(e) => {
            text("responder_result", "error");
            text("error", &e.to_string());
        }
    }
    flush();
}

fn verify_ik_responder(secp: &Secp256k1<secp256k1::All>) {
    let resp_kp = keypair(secp);
    let mut resp = HandshakeState::new_responder(resp_kp);
    resp.set_local_epoch(epoch());
    line("responder_static", &PublicKey::from_keypair(&resp_kp).serialize());
    text("ready", "1");
    flush();

    let msg1 = read_hex_line();
    if let Err(e) = resp.read_message_1(&msg1) {
        text("result", "error");
        text("error", &e.to_string());
        flush();
        return;
    }
    let msg2 = resp.write_message_2().expect("write msg2");
    text("result", "ok");
    line("initiator_static", &resp.remote_static().expect("learned rs").serialize());
    line("remote_epoch", &resp.remote_epoch().expect("epoch after msg1"));
    line("msg2", &msg2);
    line("handshake_hash", &resp.handshake_hash());
    let mut sess = resp.into_session().expect("responder session");
    let ct = sess.encrypt(b"hello fips").expect("encrypt");
    line("transport_plaintext", b"hello fips");
    line("transport_ciphertext_from_responder", &ct);
    flush();

    let ct2 = read_hex_line();
    match sess.decrypt(&ct2) {
        Ok(pt) => line("initiator_plaintext", &pt),
        Err(e) => {
            text("initiator_result", "error");
            text("error", &e.to_string());
        }
    }
    flush();
}

fn verify_xk_initiator(secp: &Secp256k1<secp256k1::All>) {
    let resp_pub = PublicKey::from_slice(&read_hex_line()).unwrap_or_else(|e| {
        eprintln!("oracle: invalid responder static key: {e}");
        std::process::exit(3);
    });
    let init_kp = keypair(secp);
    let mut init = HandshakeState::new_xk_initiator(init_kp, resp_pub);
    init.set_local_epoch(epoch());
    let msg1 = init.write_xk_message_1().expect("write xk msg1");

    line("initiator_static", &PublicKey::from_keypair(&init_kp).serialize());
    line("responder_static", &resp_pub.serialize());
    line("msg1", &msg1);
    text("ready", "1");
    flush();

    let msg2 = read_hex_line();
    if let Err(e) = init.read_xk_message_2(&msg2) {
        text("result", "error");
        text("error", &e.to_string());
        flush();
        return;
    }
    let msg3 = init.write_xk_message_3().expect("write xk msg3");
    text("result", "ok");
    line("remote_epoch", &init.remote_epoch().expect("epoch after msg2"));
    line("msg3", &msg3);
    line("handshake_hash", &init.handshake_hash());
    let mut sess = init.into_session().expect("initiator session");
    let ct = sess.encrypt(b"hello fips").expect("encrypt");
    line("transport_plaintext", b"hello fips");
    line("transport_ciphertext_from_initiator", &ct);
    flush();

    let ct2 = read_hex_line();
    match sess.decrypt(&ct2) {
        Ok(pt) => line("responder_plaintext", &pt),
        Err(e) => {
            text("responder_result", "error");
            text("error", &e.to_string());
        }
    }
    flush();
}

fn verify_xk_responder(secp: &Secp256k1<secp256k1::All>) {
    let resp_kp = keypair(secp);
    let mut resp = HandshakeState::new_xk_responder(resp_kp);
    resp.set_local_epoch(epoch());
    line("responder_static", &PublicKey::from_keypair(&resp_kp).serialize());
    text("ready", "1");
    flush();

    let msg1 = read_hex_line();
    if let Err(e) = resp.read_xk_message_1(&msg1) {
        text("error", &e.to_string());
        text("msg1_result", "error");
        flush();
        return;
    }
    let msg2 = resp.write_xk_message_2().expect("write xk msg2");
    line("msg2", &msg2);
    text("msg1_result", "ok");
    flush();

    let msg3 = read_hex_line();
    if let Err(e) = resp.read_xk_message_3(&msg3) {
        text("result", "error");
        text("error", &e.to_string());
        flush();
        return;
    }
    text("result", "ok");
    line("initiator_static", &resp.remote_static().expect("learned rs").serialize());
    line("remote_epoch", &resp.remote_epoch().expect("epoch after msg3"));
    line("handshake_hash", &resp.handshake_hash());
    let mut sess = resp.into_session().expect("responder session");
    let ct = sess.encrypt(b"hello fips").expect("encrypt");
    line("transport_plaintext", b"hello fips");
    line("transport_ciphertext_from_responder", &ct);
    flush();

    let ct2 = read_hex_line();
    match sess.decrypt(&ct2) {
        Ok(pt) => line("initiator_plaintext", &pt),
        Err(e) => {
            text("initiator_result", "error");
            text("error", &e.to_string());
        }
    }
    flush();
}

fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    rand::rng().fill_bytes(&mut b);
    u32::from_le_bytes(b)
}

/// One established frame, sealed as upstream's inline send path does it.
fn seal_frame(
    sess: &mut fips_oracle::noise::NoiseSession,
    their_index: SessionIndex,
    flags: u8,
    timestamp_ms: u32,
    plaintext: &[u8],
) -> Vec<u8> {
    let inner_plaintext = prepend_inner_header(timestamp_ms, plaintext);
    let payload_len = inner_plaintext.len() as u16;
    let counter = sess.current_send_counter();
    let header = build_established_header(their_index, counter, flags, payload_len);
    let ciphertext = sess
        .encrypt_with_aad(&inner_plaintext, &header)
        .expect("encrypt_with_aad");
    build_encrypted(&header, &ciphertext)
}

fn verify_frame(secp: &Secp256k1<secp256k1::All>) {
    let resp_pub = PublicKey::from_slice(&read_hex_line()).unwrap_or_else(|e| {
        eprintln!("oracle: invalid responder static key: {e}");
        std::process::exit(3);
    });
    let init_kp = keypair(secp);
    let mut init = HandshakeState::new_initiator(init_kp, resp_pub);
    init.set_local_epoch(epoch());
    let msg1 = init.write_message_1().expect("write msg1");
    line("initiator_static", &PublicKey::from_keypair(&init_kp).serialize());
    line("msg1", &msg1);
    text("ready", "1");
    flush();

    let msg2 = read_hex_line();
    if let Err(e) = init.read_message_2(&msg2) {
        text("result", "error");
        text("error", &e.to_string());
        flush();
        return;
    }
    text("result", "ok");
    line("handshake_hash", &init.handshake_hash());
    line("remote_epoch", &init.remote_epoch().expect("epoch after msg2"));
    let mut sess = init.into_session().expect("initiator session");

    let lisp_idx = SessionIndex::new(random_u32());
    let our_idx = random_u32();
    text("lisp_receiver_idx", &lisp_idx.as_u32().to_string());
    text("oracle_receiver_idx", &our_idx.to_string());

    let mut big = vec![0x12u8];
    big.extend((0..600u32).map(|i| (i * 7 + 3) as u8));
    let frames: [(u8, u32, Vec<u8>); 3] = [
        (0, 1000, [&[0x10u8][..], b"frame zero"].concat()),
        (FLAG_CE | FLAG_SP, 2000, [&[0x11u8][..], b"frame one"].concat()),
        (FLAG_KEY_EPOCH, u32::MAX, big),
    ];
    for (i, (flags, ts, msg)) in frames.iter().enumerate() {
        let wire = seal_frame(&mut sess, lisp_idx, *flags, *ts, msg);
        line(&format!("frame_{i}"), &wire);
        text(&format!("frame_{i}_flags"), &flags.to_string());
        text(&format!("frame_{i}_timestamp"), &ts.to_string());
        line(&format!("frame_{i}_message"), msg);
    }
    text("frames_ready", "1");
    flush();

    loop {
        let mut l = String::new();
        if std::io::stdin().lock().read_line(&mut l).unwrap_or(0) == 0 {
            return;
        }
        let l = l.trim();
        if l == "end" {
            return;
        }
        let data = match hex::decode(l) {
            Ok(d) => d,
            Err(e) => {
                text("error", &format!("bad hex: {e}"));
                text("frame_result", "error");
                flush();
                continue;
            }
        };
        let header = match EncryptedHeader::parse(&data) {
            Some(h) => h,
            None => {
                text("error", "malformed header");
                text("frame_result", "error");
                flush();
                continue;
            }
        };
        let ct = &data[header.ciphertext_offset()..];
        match sess.decrypt_with_replay_check_and_aad(ct, header.counter, &header.header_bytes) {
            Err(e) => {
                text("error", &e.to_string());
                text("frame_result", "error");
            }
            Ok(pt) => match strip_inner_header(&pt) {
                None => {
                    text("error", "inner header too short");
                    text("frame_result", "error");
                }
                Some((ts, msg)) => {
                    text("frame_receiver_idx", &header.receiver_idx.as_u32().to_string());
                    text("frame_counter", &header.counter.to_string());
                    text("frame_flags", &header.flags.to_string());
                    text("frame_timestamp", &ts.to_string());
                    let ok = header.payload_len as usize == data.len() - ESTABLISHED_HEADER_SIZE - 16;
                    text("frame_payload_len_ok", if ok { "1" } else { "0" });
                    line("frame_message", msg);
                    text("frame_result", "ok");
                }
            },
        }
        flush();
    }
}

/// identity/node_addr.rs NodeAddr::from_pubkey @ 57bc510, body verbatim.
fn node_addr_from_pubkey(pubkey: &secp256k1::XOnlyPublicKey) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pubkey.serialize());
    let hash = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    bytes
}

/// identity/address.rs FipsAddress::from_node_addr @ 57bc510, body verbatim
/// (FIPS_ADDRESS_PREFIX = 0xfd, identity/mod.rs).
fn fips_address_from_node_addr(node_addr: &[u8; 16]) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[0] = 0xfd;
    bytes[1..16].copy_from_slice(&node_addr[0..15]);
    bytes
}

fn node_addr_mode() {
    let stdin = std::io::stdin();
    let mut l = String::new();
    while stdin.lock().read_line(&mut l).unwrap_or(0) > 0 {
        let pk = PublicKey::from_slice(&hex::decode(l.trim()).expect("hex")).expect("pubkey");
        let na = node_addr_from_pubkey(&pk.x_only_public_key().0);
        line("node_addr", &na);
        line("address", &fips_address_from_node_addr(&na));
        flush();
        l.clear();
    }
}

fn main() {
    let secp = Secp256k1::new();
    match std::env::args().nth(1).as_deref() {
        Some("ik") => ik(&secp),
        Some("xk") => xk(&secp),
        Some("verify-ik-initiator") => verify_ik_initiator(&secp),
        Some("verify-ik-responder") => verify_ik_responder(&secp),
        Some("verify-xk-initiator") => verify_xk_initiator(&secp),
        Some("verify-xk-responder") => verify_xk_responder(&secp),
        Some("verify-frame") => verify_frame(&secp),
        Some("node-addr") => node_addr_mode(),
        _ => {
            eprintln!(
                "usage: oracle ik|xk|verify-ik-initiator|verify-ik-responder|\
                 verify-xk-initiator|verify-xk-responder|verify-frame|node-addr"
            );
            std::process::exit(2);
        }
    }
}
