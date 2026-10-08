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
//!   oracle verify-xk-responder-retry | verify-xk-responder-retry-plain
//!       Upstream XK RESPONDER that accepts several deliveries of msg3.  As
//!       verify-xk-responder up to `msg1_result=ok` and msg2; then every input
//!       line is a msg3 attempt, read with upstream `try_read_xk_message_3`
//!       (or, for the -plain mode, `read_xk_message_3`), printing
//!       `attempt_result=ok|error` (+ `error=`).  On the first ok it prints
//!       handshake_hash, initiator_static and remote_epoch and stops; the line
//!       `end` (or EOF) also stops it.  This is how a corrupted first delivery
//!       followed by the genuine msg3 is put to upstream.
//!
//!   oracle verify-rekey
//!       One side of an established FMP link that can rekey, transliterating
//!       upstream's rekey path: initiate_rekey (node/handlers/rekey.rs),
//!       the RekeyRespond and rekey-msg2 arms (node/handlers/handshake.rs),
//!       cutover_to_new_session / adopt_pending / complete_drain
//!       (peer/active.rs), the pending trial in handle_encrypted_frame
//!       (node/dataplane/encrypted.rs), and cross_connection_winner
//!       (proto/fmp/core.rs, verbatim).  The Noise and wire code are the
//!       vendored upstream modules.  The link is set up as verify-frame's
//!       (upstream IK initiator; stdin line 1 the foreign static key, then the
//!       foreign msg2), printing lisp_receiver_idx / oracle_receiver_idx and
//!       `ready2=1`.  Then one command per line, each answered by `done=1`:
//!         send <hex link message>   seal on the current session to their
//!                                   index, K flag = current K: `frame=`
//!         recv <hex wire>           phase 0: `frame_result=ok|error`, `slot=
//!                                   current|previous|adopted`, frame_message,
//!                                   frame_flags, frame_counter; phase 1 (a
//!                                   rekey msg1): `msg1_result=ok` + `msg2=`, or
//!                                   `msg1_result=refused` + `reason=`; phase 2:
//!                                   `msg2_result=ok|error`
//!         rekey                     `msg1=` (a phase-0x1 packet, new index)
//!         cutover                   `cutover=ok|none` (initiator pending only)
//!         drain                     drop the previous session: `drain=ok`
//!         state                     k_bit, has_pending, pending_role,
//!                                   has_previous, our_idx, their_idx,
//!                                   oracle_node_addr, lisp_node_addr
//!         end
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
    build_msg1, build_msg2, Msg1Header, Msg2Header,
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

fn verify_xk_responder_retry(secp: &Secp256k1<secp256k1::All>, plain: bool) {
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

    loop {
        let mut l = String::new();
        if std::io::stdin().lock().read_line(&mut l).unwrap_or(0) == 0 {
            return;
        }
        let l = l.trim();
        if l == "end" {
            return;
        }
        let msg3 = hex::decode(l).unwrap_or_default();
        let r = if plain {
            resp.read_xk_message_3(&msg3)
        } else {
            resp.try_read_xk_message_3(&msg3)
        };
        match r {
            Err(e) => {
                text("error", &e.to_string());
                text("attempt_result", "error");
                flush();
            }
            Ok(()) => {
                line("handshake_hash", &resp.handshake_hash());
                line("initiator_static", &resp.remote_static().expect("learned rs").serialize());
                line("remote_epoch", &resp.remote_epoch().expect("epoch after msg3"));
                text("attempt_result", "ok");
                flush();
                return;
            }
        }
    }
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

// ---- verify-rekey -------------------------------------------------------------

/// proto/fmp/core.rs cross_connection_winner @ 57bc510, body verbatim
/// (NodeAddr there is a [u8; 16] newtype with derived Ord).
pub fn cross_connection_winner(
    our_node_addr: &[u8; 16],
    their_node_addr: &[u8; 16],
    this_is_outbound: bool,
) -> bool {
    let we_are_smaller = our_node_addr < their_node_addr;

    // Smaller node's outbound wins
    // If we're smaller: our outbound wins, our inbound loses
    // If they're smaller: our outbound loses, our inbound wins
    if we_are_smaller {
        this_is_outbound
    } else {
        !this_is_outbound
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Role {
    Initiator,
    Responder,
}

struct LinkPeer {
    kp: Keypair,
    /// The node's startup epoch: every handshake of this node carries it
    /// (`hs.set_local_epoch(self.startup_epoch())` in initiate_rekey).
    startup_epoch: [u8; 8],
    peer_pub: PublicKey,
    current: fips_oracle::noise::NoiseSession,
    our_idx: u32,
    their_idx: u32,
    k_bit: bool,
    previous: Option<(fips_oracle::noise::NoiseSession, u32)>,
    pending: Option<(fips_oracle::noise::NoiseSession, u32, u32, Role)>,
    rekey: Option<(HandshakeState, u32)>,
    our_addr: [u8; 16],
    their_addr: [u8; 16],
}

impl LinkPeer {
    /// active.rs cutover_to_new_session / handle_peer_kbit_flip, the session part.
    fn promote(&mut self) -> bool {
        match self.pending.take() {
            None => false,
            Some((s, our, their, _)) => {
                let old = std::mem::replace(&mut self.current, s);
                self.previous = Some((old, self.our_idx));
                self.our_idx = our;
                self.their_idx = their;
                true
            }
        }
    }

    fn recv_frame(&mut self, data: &[u8]) {
        let header = match EncryptedHeader::parse(data) {
            Some(h) => h,
            None => return fail_frame("malformed header"),
        };
        let idx = header.receiver_idx.as_u32();
        let known = idx == self.our_idx
            || self.previous.as_ref().is_some_and(|(_, i)| *i == idx)
            || self.pending.as_ref().is_some_and(|(_, i, _, _)| *i == idx);
        if !known {
            return fail_frame("unknown session index");
        }
        let ct = &data[header.ciphertext_offset()..];
        let received_k_bit = header.flags & FLAG_KEY_EPOCH != 0;
        // encrypted.rs: the pending trial
        let kbit_differs = received_k_bit != self.k_bit;
        let try_pending = self.pending.is_some()
            && (kbit_differs || self.pending.as_ref().map(|p| p.1) == Some(idx));
        let mut result: Option<(Vec<u8>, &str)> = None;
        if try_pending {
            let pt = self.pending.as_mut().and_then(|p| {
                p.0.decrypt_with_replay_check_and_aad(ct, header.counter, &header.header_bytes)
                    .ok()
            });
            if let Some(pt) = pt {
                // adopt_pending: promote, and take the frame's K-bit
                self.promote();
                self.k_bit = received_k_bit;
                result = Some((pt, "adopted"));
            }
        }
        if result.is_none() {
            match self
                .current
                .decrypt_with_replay_check_and_aad(ct, header.counter, &header.header_bytes)
            {
                Ok(pt) => result = Some((pt, "current")),
                Err(e) => match self.previous.as_mut() {
                    Some((prev, _)) => match prev.decrypt_with_replay_check_and_aad(
                        ct,
                        header.counter,
                        &header.header_bytes,
                    ) {
                        Ok(pt) => result = Some((pt, "previous")),
                        Err(_) => return fail_frame(&e.to_string()),
                    },
                    None => return fail_frame(&e.to_string()),
                },
            }
        }
        let (pt, slot) = result.unwrap();
        match strip_inner_header(&pt) {
            None => fail_frame("inner header too short"),
            Some((_ts, msg)) => {
                text("slot", slot);
                text("frame_flags", &header.flags.to_string());
                text("frame_counter", &header.counter.to_string());
                text("frame_receiver_idx", &idx.to_string());
                line("frame_message", msg);
                text("frame_result", "ok");
            }
        }
    }

    fn recv_msg1(&mut self, data: &[u8]) {
        let header = match Msg1Header::parse(data) {
            Some(h) => h,
            None => return refuse("malformed msg1"),
        };
        let mut hs = HandshakeState::new_responder(self.kp);
        hs.set_local_epoch(self.startup_epoch);
        if let Err(e) = hs.read_message_1(&data[header.noise_msg1_offset..]) {
            return refuse(&e.to_string());
        }
        if hs.remote_static().map(|k| k.x_only_public_key().0)
            != Some(self.peer_pub.x_only_public_key().0)
        {
            return refuse("not this peer");
        }
        let noise_msg2 = hs.write_message_2().expect("write msg2");
        // core.rs establish_inbound, the same-epoch rekey arm
        if self.pending.is_some() {
            return refuse("pending session");
        }
        if self.rekey.is_some() {
            if cross_connection_winner(&self.our_addr, &self.their_addr, true) {
                return refuse("dual rekey won");
            }
            self.rekey = None; // abandon_rekey: we lose
        }
        let new_idx = random_u32();
        let wire = build_msg2(SessionIndex::new(new_idx), header.sender_idx, &noise_msg2);
        let session = hs.into_session().expect("responder session");
        self.pending = Some((session, new_idx, header.sender_idx.as_u32(), Role::Responder));
        line("msg2", &wire);
        text("msg1_result", "ok");
    }

    fn recv_msg2(&mut self, data: &[u8]) {
        let header = match Msg2Header::parse(data) {
            Some(h) => h,
            None => {
                text("error", "malformed msg2");
                return text("msg2_result", "error");
            }
        };
        let rekey_idx = match &self.rekey {
            Some((_, i)) if *i == header.receiver_idx.as_u32() => *i,
            _ => {
                text("error", "no rekey for this index");
                return text("msg2_result", "error");
            }
        };
        let (mut hs, _) = self.rekey.take().unwrap();
        // active.rs complete_rekey_msg2: the rolling-back read keeps the cycle
        if let Err(e) = hs.try_read_message_2(&data[header.noise_msg2_offset..]) {
            self.rekey = Some((hs, rekey_idx));
            text("error", &e.to_string());
            return text("msg2_result", "error");
        }
        let session = hs.into_session().expect("initiator session");
        self.pending = Some((session, rekey_idx, header.sender_idx.as_u32(), Role::Initiator));
        text("msg2_result", "ok");
    }
}

fn fail_frame(e: &str) {
    text("error", e);
    text("frame_result", "error");
}

fn refuse(reason: &str) {
    text("reason", reason);
    text("msg1_result", "refused");
}

fn verify_rekey(secp: &Secp256k1<secp256k1::All>) {
    let peer_pub = PublicKey::from_slice(&read_hex_line()).unwrap_or_else(|e| {
        eprintln!("oracle: invalid foreign static key: {e}");
        std::process::exit(3);
    });
    let kp = keypair(secp);
    let startup_epoch = epoch();
    let mut init = HandshakeState::new_initiator(kp, peer_pub);
    init.set_local_epoch(startup_epoch);
    let msg1 = init.write_message_1().expect("write msg1");
    line("initiator_static", &PublicKey::from_keypair(&kp).serialize());
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
    let current = init.into_session().expect("initiator session");
    let their_idx = random_u32();
    let our_idx = random_u32();
    text("lisp_receiver_idx", &their_idx.to_string());
    text("oracle_receiver_idx", &our_idx.to_string());
    text("ready2", "1");
    flush();

    let mut p = LinkPeer {
        kp,
        startup_epoch,
        peer_pub,
        current,
        our_idx,
        their_idx,
        k_bit: false,
        previous: None,
        pending: None,
        rekey: None,
        our_addr: node_addr_from_pubkey(&PublicKey::from_keypair(&kp).x_only_public_key().0),
        their_addr: node_addr_from_pubkey(&peer_pub.x_only_public_key().0),
    };

    loop {
        let mut l = String::new();
        if std::io::stdin().lock().read_line(&mut l).unwrap_or(0) == 0 {
            return;
        }
        let mut parts = l.trim().splitn(2, ' ');
        let cmd = parts.next().unwrap_or("");
        let arg = hex::decode(parts.next().unwrap_or("")).unwrap_or_default();
        match cmd {
            "end" => return,
            "send" => {
                let flags = if p.k_bit { FLAG_KEY_EPOCH } else { 0 };
                let wire = seal_frame(&mut p.current, SessionIndex::new(p.their_idx), flags, 0, &arg);
                line("frame", &wire);
            }
            "recv" => match arg.first().map(|b| b & 0x0F) {
                Some(0) => p.recv_frame(&arg),
                Some(1) => p.recv_msg1(&arg),
                Some(2) => p.recv_msg2(&arg),
                _ => text("error", "unknown phase"),
            },
            "rekey" => {
                let idx = random_u32();
                let mut hs = HandshakeState::new_initiator(p.kp, p.peer_pub);
                hs.set_local_epoch(p.startup_epoch);
                let noise = hs.write_message_1().expect("write rekey msg1");
                line("msg1", &build_msg1(SessionIndex::new(idx), &noise));
                p.rekey = Some((hs, idx));
            }
            "cutover" => {
                let initiated = p.pending.as_ref().is_some_and(|x| x.3 == Role::Initiator);
                if initiated && p.rekey.is_none() && p.promote() {
                    p.k_bit = !p.k_bit;
                    text("cutover", "ok");
                } else {
                    text("cutover", "none");
                }
            }
            "drain" => {
                p.previous = None;
                text("drain", "ok");
            }
            "state" => {
                text("k_bit", if p.k_bit { "1" } else { "0" });
                text("has_pending", if p.pending.is_some() { "1" } else { "0" });
                text(
                    "pending_role",
                    match p.pending.as_ref().map(|x| x.3) {
                        Some(Role::Initiator) => "initiator",
                        Some(Role::Responder) => "responder",
                        None => "none",
                    },
                );
                text("has_previous", if p.previous.is_some() { "1" } else { "0" });
                text("our_idx", &p.our_idx.to_string());
                text("their_idx", &p.their_idx.to_string());
                line("oracle_node_addr", &p.our_addr);
                line("lisp_node_addr", &p.their_addr);
            }
            _ => text("error", "unknown command"),
        }
        text("done", "1");
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
        Some("verify-xk-responder-retry") => verify_xk_responder_retry(&secp, false),
        Some("verify-xk-responder-retry-plain") => verify_xk_responder_retry(&secp, true),
        Some("verify-rekey") => verify_rekey(&secp),
        Some("node-addr") => node_addr_mode(),
        _ => {
            eprintln!(
                "usage: oracle ik|xk|verify-ik-initiator|verify-ik-responder|\
                 verify-xk-initiator|verify-xk-responder|verify-frame|node-addr|\
                 verify-xk-responder-retry[-plain]|verify-rekey"
            );
            std::process::exit(2);
        }
    }
}
