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
//! Output is one `name=hex` line per field (`result`/`error` lines are text).
//! Keys and ephemerals are random per run, so the output is a transcript to
//! verify against, not a fixed fixture.

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

fn main() {
    let secp = Secp256k1::new();
    match std::env::args().nth(1).as_deref() {
        Some("ik") => ik(&secp),
        Some("xk") => xk(&secp),
        Some("verify-ik-initiator") => verify_ik_initiator(&secp),
        Some("verify-ik-responder") => verify_ik_responder(&secp),
        _ => {
            eprintln!("usage: oracle ik|xk|verify-ik-initiator|verify-ik-responder");
            std::process::exit(2);
        }
    }
}
