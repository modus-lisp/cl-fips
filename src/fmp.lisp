;;;; fmp.lisp -- FMP established frames: the link layer after the IK handshake.
;;;;
;;;; Authority: upstream jmcorgan/fips @ 57bc510.
;;;;   src/proto/fmp/wire.rs   build_established_header, EncryptedHeader::parse,
;;;;                           prepend_inner_header, strip_inner_header
;;;;   src/node/mod.rs         the inline send path: inner = ts || link message,
;;;;                           payload_len = |inner|, counter = the session's
;;;;                           current send counter, AEAD AAD = the 16-byte header
;;;;   src/node/dataplane/encrypted.rs  the receive path: parse, replay check,
;;;;                           decrypt_with_replay_check_and_aad, strip
;;;;
;;;; Wire:  header(16) || ChaCha20-Poly1305(inner, nonce = counter, aad = header)
;;;;   header = [0x00][flags][payload_len u16 LE][receiver_idx u32 LE][counter u64 LE]
;;;;   inner  = [timestamp_ms u32 LE][msg_type][body]
;;;;
;;;; Two places where upstream's RECEIVE path is looser than the docs, and this
;;;; file follows upstream (both fields are inside the AAD, so a sender cannot
;;;; alter them after sealing): the reserved flag bits 3-7 are not rejected, and
;;;; payload_len is not compared against the frame length (the stream framer in
;;;; transport/framing.rs uses it to delimit; a datagram parse ignores it).
;;;; FMP-FRAME-PAYLOAD-LEN-OK-P exposes the comparison for a caller that wants it.

(in-package #:cl-fips)

(defconstant +fmp-version+ 0)
(defconstant +inner-header-size+ 5 "timestamp(4) + msg_type(1).")
(defconstant +flag-key-epoch+ #x01)
(defconstant +flag-ce+ #x02)
(defconstant +flag-sp+ #x04)

(defun u8-vector (n) (make-array n :element-type '(unsigned-byte 8) :initial-element 0))

(defun u8-append (a b)
  (let ((out (u8-vector (+ (length a) (length b)))))
    (replace out a)
    (replace out b :start1 (length a))
    out))

(defun fmp-seal-frame (session receiver-idx timestamp-ms link-message &key (flags 0))
  "Seal LINK-MESSAGE ([msg_type][body]) into an established frame addressed to
   RECEIVER-IDX, with the session's next send counter.  Returns the wire bytes."
  (let* ((inner (u8-append (encode-u32le timestamp-ms) link-message))
         (payload-len (length inner)))
    (unless (< payload-len 65536) (error "FMP payload too large: ~d bytes" payload-len))
    (unless (zerop (logand flags #xf8)) (error "FMP reserved flag bits set: #x~2,'0x" flags))
    (let* ((counter (natrium.noise:session-current-send-counter session))
           (header (encode-fmp-established-header flags payload-len receiver-idx counter))
           (ct (natrium.noise:session-encrypt-with-aad session inner header)))
      (u8-append header ct))))

(defun fmp-frame-payload-len-ok-p (wire)
  (= (decode-u16le wire 2) (- (length wire) +fmp-established-header-size+ +aead-tag-size+)))

(defun fmp-open-frame (session wire)
  "Open an established frame.  Signals NATRIUM.NOISE:NOISE-ERROR if it is
   malformed, replayed or too old, fails authentication, or decrypts to less
   than the inner header -- the cases upstream drops.  The counter enters the
   replay window only once the AEAD has opened.  Returns
   (values link-message timestamp-ms flags receiver-idx counter), where
   LINK-MESSAGE starts at msg_type."
  (when (< (length wire) (+ +fmp-established-header-size+ +aead-tag-size+))
    (error 'natrium.noise:noise-error :reason "frame shorter than header + tag"))
  (unless (and (= (prefix-version wire) +fmp-version+)
               (= (prefix-phase wire) +phase-established+))
    (error 'natrium.noise:noise-error :reason "not an FMP v0 established frame"))
  (multiple-value-bind (flags payload-len receiver-idx counter)
      (decode-fmp-established-header wire)
    (declare (ignore payload-len))
    (let* ((header (subseq wire 0 +fmp-established-header-size+))
           (ct (subseq wire +fmp-established-header-size+))
           (inner (natrium.noise:session-decrypt-with-replay-check session counter ct header)))
      (when (< (length inner) +inner-header-size+)
        (error 'natrium.noise:noise-error :reason "inner header too short"))
      (values (subseq inner 4) (decode-u32le inner 0) flags receiver-idx counter))))
