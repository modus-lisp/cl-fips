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
//!   oracle serve-tcp
//!       Upstream IK RESPONDER over REAL TCP.  Listens on 127.0.0.1, an
//!       ephemeral port; prints responder_static, port and `ready=1`.  Accepts
//!       one connection and reads packets with read_fmp_packet (framing.rs,
//!       transliterated to blocking I/O; MTU 1400): the msg1 is parsed with
//!       Msg1Header::parse and read with read_message_1, and the msg2 written
//!       with write_message_2 + build_msg2.  Prints result (or `error=`),
//!       handshake_hash, initiator_static, remote_epoch, lisp_receiver_idx and
//!       oracle_receiver_idx, then the stream exchange below.
//!
//!   oracle dial-tcp
//!       Upstream IK INITIATOR over REAL TCP.  stdin line 1: the port (decimal)
//!       to dial on 127.0.0.1; line 2: the responder's static key (hex).
//!       Writes build_msg1, reads the msg2 packet with read_fmp_packet +
//!       Msg2Header::parse (receiver_idx must be ours) + read_message_2, prints
//!       the same fields as serve-tcp, then the stream exchange.
//!
//!       The stream exchange (both modes): verify-frame's three frames, printed
//!       as frame_N / _flags / _timestamp / _message and `frames_ready=1`, then
//!       written to the socket.  Then every packet read is opened as
//!       verify-frame opens a line (frame_receiver_idx, frame_counter,
//!       frame_flags, frame_timestamp, frame_payload_len_ok, frame_message,
//!       `frame_result=ok`, or `error=` + `frame_result=error`); each opened
//!       frame is ECHOED back sealed on the session (same message, timestamp
//!       + 1, flags 0).  The first read_fmp_packet error ends it, printed as
//!       `stream_end=<StreamError>` and `frames_received=N`.
//!
//!   oracle dial-raw
//!       A raw TCP peer for malformed-input tests.  One command per stdin line:
//!       `connect <port>`, `send <hex>`, `sleep <ms>`, `shutdown` (our write
//!       half), `wait-close <ms>` (read and discard until the peer closes or
//!       <ms> pass, printing peer_closed=1|0, close_kind=eof|reset|timeout,
//!       waited_ms, bytes_received), `end`.  Each command prints `ok=<cmd>`.
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
use fips_oracle::framing::read_fmp_packet;
use fips_oracle::noise::{HandshakeState, NoiseSession};
use std::io::{BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};
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

// ---- serve-tcp / dial-tcp / dial-raw ----------------------------------------------

const TCP_MTU: u16 = 1400;

/// The stream exchange shared by serve-tcp and dial-tcp (see the header).
fn tcp_exchange(stream: &mut TcpStream, sess: &mut NoiseSession, lisp_idx: SessionIndex, our_idx: u32) {
    let mut big = vec![0x12u8];
    big.extend((0..600u32).map(|i| (i * 7 + 3) as u8));
    let frames: [(u8, u32, Vec<u8>); 3] = [
        (0, 1000, [&[0x10u8][..], b"frame zero"].concat()),
        (FLAG_CE | FLAG_SP, 2000, [&[0x11u8][..], b"frame one"].concat()),
        (FLAG_KEY_EPOCH, u32::MAX, big),
    ];
    let mut out = Vec::new();
    for (i, (flags, ts, msg)) in frames.iter().enumerate() {
        let wire = seal_frame(sess, lisp_idx, *flags, *ts, msg);
        line(&format!("frame_{i}"), &wire);
        text(&format!("frame_{i}_flags"), &flags.to_string());
        text(&format!("frame_{i}_timestamp"), &ts.to_string());
        line(&format!("frame_{i}_message"), msg);
        out.extend_from_slice(&wire);
    }
    text("frames_ready", "1");
    flush();
    if let Err(e) = stream.write_all(&out) {
        text("stream_end", &format!("write: {e}"));
        text("frames_received", "0");
        flush();
        return;
    }
    let mut n = 0u32;
    loop {
        let data = match read_fmp_packet(stream, TCP_MTU) {
            Ok(d) => d,
            Err(e) => {
                text("stream_end", &e.to_string());
                text("frames_received", &n.to_string());
                flush();
                return;
            }
        };
        let header = match EncryptedHeader::parse(&data) {
            Some(h) => h,
            None => {
                text("error", "not an established frame");
                text("frame_result", "error");
                flush();
                continue;
            }
        };
        if header.receiver_idx.as_u32() != our_idx {
            text("error", "frame for another receiver_idx");
            text("frame_result", "error");
            flush();
            continue;
        }
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
                    n += 1;
                    text("frame_receiver_idx", &header.receiver_idx.as_u32().to_string());
                    text("frame_counter", &header.counter.to_string());
                    text("frame_flags", &header.flags.to_string());
                    text("frame_timestamp", &ts.to_string());
                    let ok = header.payload_len as usize == data.len() - ESTABLISHED_HEADER_SIZE - 16;
                    text("frame_payload_len_ok", if ok { "1" } else { "0" });
                    line("frame_message", msg);
                    let msg = msg.to_vec();
                    let echo = seal_frame(sess, lisp_idx, 0, ts.wrapping_add(1), &msg);
                    text("frame_result", "ok");
                    flush();
                    if let Err(e) = stream.write_all(&echo) {
                        text("echo_error", &e.to_string());
                    }
                }
            },
        }
        flush();
    }
}

fn read_text_line() -> String {
    let mut l = String::new();
    if std::io::stdin().lock().read_line(&mut l).unwrap_or(0) == 0 {
        eprintln!("oracle: unexpected end of input");
        std::process::exit(3);
    }
    l.trim().to_string()
}

fn serve_tcp(secp: &Secp256k1<secp256k1::All>) {
    let resp_kp = keypair(secp);
    let mut resp = HandshakeState::new_responder(resp_kp);
    resp.set_local_epoch(epoch());
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    line("responder_static", &PublicKey::from_keypair(&resp_kp).serialize());
    text("port", &listener.local_addr().expect("local addr").port().to_string());
    text("ready", "1");
    flush();
    let (mut stream, _) = listener.accept().expect("accept");
    drop(listener);
    stream.set_read_timeout(Some(Duration::from_secs(20))).ok();
    let packet = match read_fmp_packet(&mut stream, TCP_MTU) {
        Ok(p) => p,
        Err(e) => {
            text("result", "error");
            text("error", &e.to_string());
            flush();
            return;
        }
    };
    let header = match Msg1Header::parse(&packet) {
        Some(h) => h,
        None => {
            text("result", "error");
            text("error", "malformed msg1");
            flush();
            return;
        }
    };
    if let Err(e) = resp.read_message_1(&packet[header.noise_msg1_offset..]) {
        text("result", "error");
        text("error", &e.to_string());
        flush();
        return;
    }
    let msg2 = resp.write_message_2().expect("write msg2");
    let our_idx = random_u32();
    let wire = build_msg2(SessionIndex::new(our_idx), header.sender_idx, &msg2);
    text("result", "ok");
    line("handshake_hash", &resp.handshake_hash());
    line("initiator_static", &resp.remote_static().expect("learned rs").serialize());
    line("remote_epoch", &resp.remote_epoch().expect("epoch after msg1"));
    text("lisp_receiver_idx", &header.sender_idx.as_u32().to_string());
    text("oracle_receiver_idx", &our_idx.to_string());
    flush();
    let mut sess = resp.into_session().expect("responder session");
    stream.write_all(&wire).expect("write msg2");
    tcp_exchange(&mut stream, &mut sess, header.sender_idx, our_idx);
}

fn dial_tcp(secp: &Secp256k1<secp256k1::All>) {
    let port: u16 = read_text_line().parse().expect("port");
    let resp_pub = PublicKey::from_slice(&read_hex_line()).unwrap_or_else(|e| {
        eprintln!("oracle: invalid responder static key: {e}");
        std::process::exit(3);
    });
    let init_kp = keypair(secp);
    let mut init = HandshakeState::new_initiator(init_kp, resp_pub);
    init.set_local_epoch(epoch());
    let msg1 = init.write_message_1().expect("write msg1");
    let our_idx = random_u32();
    line("initiator_static", &PublicKey::from_keypair(&init_kp).serialize());
    flush();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(20))).ok();
    stream.write_all(&build_msg1(SessionIndex::new(our_idx), &msg1)).expect("write msg1");
    let packet = match read_fmp_packet(&mut stream, TCP_MTU) {
        Ok(p) => p,
        Err(e) => {
            text("result", "error");
            text("error", &e.to_string());
            flush();
            return;
        }
    };
    let header = match Msg2Header::parse(&packet) {
        Some(h) if h.receiver_idx.as_u32() == our_idx => h,
        _ => {
            text("result", "error");
            text("error", "malformed msg2 or wrong receiver_idx");
            flush();
            return;
        }
    };
    if let Err(e) = init.read_message_2(&packet[header.noise_msg2_offset..]) {
        text("result", "error");
        text("error", &e.to_string());
        flush();
        return;
    }
    text("result", "ok");
    line("handshake_hash", &init.handshake_hash());
    line("remote_epoch", &init.remote_epoch().expect("epoch after msg2"));
    text("lisp_receiver_idx", &header.sender_idx.as_u32().to_string());
    text("oracle_receiver_idx", &our_idx.to_string());
    flush();
    let mut sess = init.into_session().expect("initiator session");
    tcp_exchange(&mut stream, &mut sess, header.sender_idx, our_idx);
}

fn dial_raw() {
    let mut stream: Option<TcpStream> = None;
    loop {
        let mut l = String::new();
        if std::io::stdin().lock().read_line(&mut l).unwrap_or(0) == 0 {
            return;
        }
        let mut parts = l.trim().splitn(2, ' ');
        let cmd = parts.next().unwrap_or("");
        let arg = parts.next().unwrap_or("");
        match cmd {
            "end" => return,
            "connect" => {
                stream = Some(TcpStream::connect(("127.0.0.1", arg.parse::<u16>().expect("port")))
                    .expect("connect"));
            }
            "send" => {
                let s = stream.as_mut().expect("connected");
                if let Err(e) = s.write_all(&hex::decode(arg).expect("hex")) {
                    text("send_error", &e.to_string());
                }
            }
            "sleep" => std::thread::sleep(Duration::from_millis(arg.parse().expect("ms"))),
            "shutdown" => {
                let _ = stream.as_ref().expect("connected").shutdown(std::net::Shutdown::Write);
            }
            "wait-close" => {
                let s = stream.as_mut().expect("connected");
                let limit = Duration::from_millis(arg.parse().expect("ms"));
                let start = Instant::now();
                let mut got = 0usize;
                let mut buf = [0u8; 4096];
                let kind = loop {
                    let left = limit.saturating_sub(start.elapsed());
                    if left.is_zero() {
                        break "timeout";
                    }
                    s.set_read_timeout(Some(left)).ok();
                    match s.read(&mut buf) {
                        Ok(0) => break "eof",
                        Ok(k) => got += k,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut => break "timeout",
                        Err(_) => break "reset",
                    }
                };
                text("peer_closed", if kind == "timeout" { "0" } else { "1" });
                text("close_kind", kind);
                text("waited_ms", &start.elapsed().as_millis().to_string());
                text("bytes_received", &got.to_string());
            }
            _ => text("error", "unknown command"),
        }
        text("ok", cmd);
        flush();
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
        Some("serve-tcp") => serve_tcp(&secp),
        Some("dial-tcp") => dial_tcp(&secp),
        Some("dial-raw") => dial_raw(),
        _ => {
            eprintln!(
                "usage: oracle ik|xk|verify-ik-initiator|verify-ik-responder|\
                 verify-xk-initiator|verify-xk-responder|verify-frame|node-addr|\
                 verify-xk-responder-retry[-plain]|verify-rekey|serve-tcp|dial-tcp|dial-raw"
            );
            std::process::exit(2);
        }
    }
}
